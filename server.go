package newdns

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Config provides configuration for a DNS server.
type Config struct {
	// The buffer size used if EDNS is enabled by a client.
	//
	// Default: 1220.
	BufferSize int

	// Handler is the callback that returns a zone for the specified name.
	Handler func(name string) (*Zone, error)

	// Reporter is the callback called with request errors.
	Reporter func(error)
}

// Server is a DNS server.
type Server struct {
	config Config
	close  chan struct{}
}

// NewServer creates and returns a new DNS server.
func NewServer(config Config) *Server {
	// set default buffer size
	if config.BufferSize <= 0 {
		config.BufferSize = 1220
	}

	return &Server{
		config: config,
		close:  make(chan struct{}),
	}
}

// Run will run a udp and tcp server on the specified address. It will return
// on the first accept error and close all servers.
func (s *Server) Run(addr string) error {
	// register handler
	dns.HandleFunc(".", s.handler)

	// prepare servers
	udp := &dns.Server{Addr: addr, Net: "udp", MsgAcceptFunc: s.accept}
	tcp := &dns.Server{Addr: addr, Net: "tcp", MsgAcceptFunc: s.accept}

	// prepare errors
	errs := make(chan error, 2)

	// run udp server
	go func() {
		errs <- udp.ListenAndServe()
	}()

	// run tcp server
	go func() {
		errs <- tcp.ListenAndServe()
	}()

	// await first error
	var err error
	select {
	case err = <-errs:
	case <-s.close:
	}

	// shutdown servers
	_ = udp.Shutdown()
	_ = tcp.Shutdown()

	return err
}

// Close will close the server.
func (s *Server) Close() {
	close(s.close)
}

func (s *Server) accept(dh dns.Header) dns.MsgAcceptAction {
	// check if query
	if dh.Bits&(1<<15) != 0 {
		return dns.MsgIgnore
	}

	// check opcode
	if int(dh.Bits>>11)&0xF != dns.OpcodeQuery {
		return dns.MsgIgnore
	}

	// check question count
	if dh.Qdcount != 1 {
		return dns.MsgIgnore
	}

	return dns.MsgAccept
}

func (s *Server) handler(w dns.ResponseWriter, rq *dns.Msg) {
	// prepare response
	rs := new(dns.Msg)
	rs.SetReply(rq)

	// always compress responses
	rs.Compress = true

	// set flag
	rs.Authoritative = true

	// check edns
	if rq.IsEdns0() != nil {
		// use edns in reply
		rs.SetEdns0(uint16(s.config.BufferSize), false)

		// check version
		if rq.IsEdns0().Version() != 0 {
			s.writeError(w, rq, rs, nil, dns.RcodeBadVers)
			return
		}
	}

	// get question
	question := rq.Question[0]

	// check class
	if question.Qclass != dns.ClassINET {
		// leave connection hanging
		return
	}

	// check any type
	if question.Qtype == dns.TypeANY {
		s.writeError(w, rq, rs, nil, dns.RcodeNotImplemented)
		return
	}

	// get name
	name := strings.ToLower(dns.Name(question.Name).String())

	// get zone
	zone, err := s.config.Handler(name)
	if err != nil {
		s.writeError(w, rq, rs, nil, dns.RcodeServerFailure)
		s.reportError(rq, err.Error())
		return
	}

	// check zone
	if zone == nil {
		rs.Authoritative = false
		s.writeError(w, rq, rs, nil, dns.RcodeRefused)
		return
	}

	// validate zone
	err = zone.Validate()
	if err != nil {
		s.writeError(w, rq, rs, nil, dns.RcodeServerFailure)
		s.reportError(rq, err.Error())
		return
	}

	// answer SOA directly
	if question.Qtype == dns.TypeSOA && name == zone.Name {
		s.writeSOAResponse(w, rq, rs, zone)
		return
	}

	// answer NS directly
	if question.Qtype == dns.TypeNS && name == zone.Name {
		s.writeNSResponse(w, rq, rs, zone)
		return
	}

	// check type
	typ := Type(question.Qtype)

	// return error if type is not supported
	if !typ.valid() {
		s.writeError(w, rq, rs, zone, dns.RcodeNameError)
		return
	}

	// lookup main result
	result, exists, err := zone.Lookup(name, typ)
	if err != nil {
		s.writeError(w, rq, rs, nil, dns.RcodeServerFailure)
		s.reportError(rq, err.Error())
		return
	}

	// check result
	if len(result) == 0 {
		// write SOA with success code to indicate existence of other sets
		if exists {
			s.writeError(w, rq, rs, zone, dns.RcodeSuccess)
			return
		}

		// otherwise return name error
		s.writeError(w, rq, rs, zone, dns.RcodeNameError)

		return
	}

	// set answer
	for _, res := range result {
		rs.Answer = append(rs.Answer, s.convert(question.Name, zone, res)...)
	}

	// check answers
	for _, answer := range rs.Answer {
		switch record := answer.(type) {
		case *dns.MX:
			// lookup internal MX target A and AAAA records
			if InZone(zone.Name, record.Mx) {
				result, _, err = zone.Lookup(record.Mx, A, AAAA)
				if err != nil {
					s.writeError(w, rq, rs, nil, dns.RcodeServerFailure)
					s.reportError(rq, err.Error())
					return
				}

				// add results to extra
				for _, res := range result {
					rs.Extra = append(rs.Extra, s.convert(question.Name, zone, res)...)
				}
			}
		}
	}

	// add ns records
	for _, ns := range zone.AllNameServers {
		rs.Ns = append(rs.Ns, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   transferCase(question.Name, zone.Name),
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    durationToTime(zone.NSTTL),
			},
			Ns: ns,
		})
	}

	// write message
	s.writeMessage(w, rq, rs)
}

func (s *Server) writeSOAResponse(w dns.ResponseWriter, rq, rs *dns.Msg, zone *Zone) {
	// add soa record
	rs.Answer = append(rs.Answer, &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zone.Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    durationToTime(zone.SOATTL),
		},
		Ns:      zone.MasterNameServer,
		Mbox:    emailToDomain(zone.AdminEmail),
		Serial:  1,
		Refresh: durationToTime(zone.Refresh),
		Retry:   durationToTime(zone.Retry),
		Expire:  durationToTime(zone.Expire),
		Minttl:  durationToTime(zone.MinTTL),
	})

	// add ns records
	for _, ns := range zone.AllNameServers {
		rs.Ns = append(rs.Ns, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   zone.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    durationToTime(zone.NSTTL),
			},
			Ns: ns,
		})
	}

	// write message
	s.writeMessage(w, rq, rs)
}

func (s *Server) writeNSResponse(w dns.ResponseWriter, rq, rs *dns.Msg, zone *Zone) {
	// add ns records
	for _, ns := range zone.AllNameServers {
		rs.Answer = append(rs.Answer, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   zone.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    durationToTime(zone.NSTTL),
			},
			Ns: ns,
		})
	}

	// write message
	s.writeMessage(w, rq, rs)
}

func (s *Server) writeError(w dns.ResponseWriter, rq, rs *dns.Msg, zone *Zone, code int) {
	// set code
	rs.Rcode = code

	// add soa record
	if zone != nil {
		rs.Ns = append(rs.Ns, &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   zone.Name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    durationToTime(zone.SOATTL),
			},
			Ns:      zone.MasterNameServer,
			Mbox:    emailToDomain(zone.AdminEmail),
			Serial:  1,
			Refresh: durationToTime(zone.Refresh),
			Retry:   durationToTime(zone.Retry),
			Expire:  durationToTime(zone.Expire),
			Minttl:  durationToTime(zone.MinTTL),
		})
	}

	// write message
	s.writeMessage(w, rq, rs)
}

func (s *Server) writeMessage(w dns.ResponseWriter, rq, rs *dns.Msg) {
	// get buffer size
	var buffer = 512
	if rq.IsEdns0() != nil {
		buffer = int(rq.IsEdns0().UDPSize())
	}

	// determine if client is using UDP
	isUDP := w.RemoteAddr().Network() == "udp"

	// return truncated message if client is using UDP and message is too long
	if isUDP && rs.Len() > buffer {
		rs.Truncated = true
		rs.Answer = nil
		rs.Ns = nil
		rs.Extra = nil
		rs.Rcode = dns.RcodeSuccess
		_ = w.WriteMsg(rs)
		_ = w.Close()
		return
	}

	// write message
	err := w.WriteMsg(rs)
	if err != nil {
		_ = w.Close()
		s.reportError(rq, err.Error())
		return
	}
}

func (s *Server) reportError(r *dns.Msg, msg string) {
	if s.config.Reporter != nil {
		s.config.Reporter(fmt.Errorf("%s: %+v", msg, r))
	}
}

func (s *Server) convert(query string, zone *Zone, set Set) []dns.RR {
	// prepare header
	header := dns.RR_Header{
		Name:   transferCase(query, set.Name),
		Rrtype: uint16(set.Type),
		Class:  dns.ClassINET,
		Ttl:    durationToTime(set.TTL),
	}

	// ensure zone min TTL
	if set.TTL < zone.MinTTL {
		header.Ttl = durationToTime(zone.MinTTL)
	}

	// prepare list
	var list []dns.RR

	// add records
	for _, record := range set.Records {
		// construct record
		switch set.Type {
		case A:
			list = append(list, &dns.A{
				Hdr: header,
				A:   net.ParseIP(record.Address),
			})
		case AAAA:
			list = append(list, &dns.AAAA{
				Hdr:  header,
				AAAA: net.ParseIP(record.Address),
			})
		case CNAME:
			list = append(list, &dns.CNAME{
				Hdr:    header,
				Target: dns.Fqdn(record.Address),
			})
		case MX:
			list = append(list, &dns.MX{
				Hdr:        header,
				Preference: uint16(record.Priority),
				Mx:         dns.Fqdn(record.Address),
			})
		case TXT:
			list = append(list, &dns.TXT{
				Hdr: header,
				Txt: record.Data,
			})
		}
	}

	return list
}
