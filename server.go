package newdns

import (
	"fmt"
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
	udp := &dns.Server{Addr: addr, Net: "udp"}
	tcp := &dns.Server{Addr: addr, Net: "tcp"}

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
		// check version
		if rq.IsEdns0().Version() != 0 {
			s.writeError(w, rs, dns.RcodeBadVers)
			s.reportError(rq, "invalid edns version")
			return
		}

		// use edns in reply
		rs.SetEdns0(uint16(s.config.BufferSize), false)
	}

	// check opcode
	if rq.Opcode != dns.OpcodeQuery {
		s.writeError(w, rs, dns.RcodeNotImplemented)
		s.reportError(rq, "opcode is not query")
		return
	}

	// ignore to less or too many questions
	if len(rq.Question) != 1 {
		s.writeError(w, rs, dns.RcodeRefused)
		s.reportError(rq, "too many questions")
		return
	}

	// get question
	question := rq.Question[0]

	// check class
	if question.Qclass != dns.ClassINET {
		s.writeError(w, rs, dns.RcodeNotImplemented)
		s.reportError(rq, "unsupported question class")
		return
	}

	// get name
	name := strings.ToLower(dns.Name(question.Name).String())

	// get zone
	zone, err := s.config.Handler(name)
	if err != nil {
		s.writeError(w, rs, dns.RcodeServerFailure)
		s.reportError(rq, err.Error())
		return
	}

	// check zone
	if zone == nil {
		s.writeError(w, rs, dns.RcodeNameError)
		return
	}

	// validate zone
	err = zone.Validate()
	if err != nil {
		s.writeError(w, rs, dns.RcodeServerFailure)
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

	// get sets
	sets, err := zone.Handler(TrimZone(zone.Name, name))
	if err != nil {
		s.writeError(w, rs, dns.RcodeServerFailure)
		s.reportError(rq, err.Error())
		return
	}

	// check sets
	if len(sets) == 0 {
		s.writeErrorWithSOA(w, rq, rs, zone, dns.RcodeNameError)
		s.reportError(rq, "no sets")
		return
	}

	// prepare flag
	isCNAME := false

	// validate sets
	for _, set := range sets {
		// check set
		err = set.Validate()
		if err != nil {
			s.writeError(w, rs, dns.RcodeServerFailure)
			s.reportError(rq, err.Error())
			return
		}

		// set flag
		if set.Type == TypeCNAME {
			isCNAME = true
		}
	}

	// check apex CNAME
	if isCNAME && name == zone.Name {
		s.writeError(w, rs, dns.RcodeServerFailure)
		s.reportError(rq, "invalid CNAME at apex")
		return
	}

	// check CNAME is stand-alone
	if isCNAME && (len(sets) > 0) {
		s.writeError(w, rs, dns.RcodeServerFailure)
		s.reportError(rq, "a CNAME set must be stand-alone")
		return
	}

	// add matching set
	for _, set := range sets {
		if uint16(set.Type) == question.Qtype {
			rs.Answer = set.convert(zone, name)
		}
	}

	// return CNAME set for A and AAAA queries
	if len(rs.Answer) == 0 && (question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA) {
		for _, set := range sets {
			if set.Type == TypeCNAME {
				rs.Answer = set.convert(zone, name)
				break
			}
		}
	}

	// write SOA with success code to indicate available other sets
	if len(rs.Answer) == 0 {
		s.writeErrorWithSOA(w, rq, rs, zone, dns.RcodeSuccess)
		s.reportError(rq, "no answer")
		return
	}

	// check if answer is a CNAME that belongs to this zone
	if cname, ok := rs.Answer[0].(*dns.CNAME); ok && InZone(zone.Name, cname.Target) {
		println("following cname", cname.Target)

		// get additional sets
		addSets, err := zone.Handler(TrimZone(zone.Name, cname.Target))
		if err != nil {
			s.writeError(w, rs, dns.RcodeServerFailure)
			s.reportError(rq, err.Error())
			return
		}

		// validate additional sets
		for _, set := range addSets {
			err = set.Validate()
			if err != nil {
				s.writeError(w, rs, dns.RcodeServerFailure)
				s.reportError(rq, err.Error())
				return
			}
		}

		// add matching A and AAAA sets
		for _, set := range addSets {
			if set.Type == TypeA || set.Type == TypeAAAA {
				rs.Answer = append(rs.Answer, set.convert(zone, cname.Target)...)
			}
		}
	}

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

func (s *Server) writeErrorWithSOA(w dns.ResponseWriter, rq, rs *dns.Msg, zone *Zone, code int) {
	// set code
	rs.Rcode = code

	// add soa record
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

	// write message
	s.writeMessage(w, rq, rs)
}

func (s *Server) writeMessage(w dns.ResponseWriter, rq, rs *dns.Msg) {
	err := w.WriteMsg(rs)
	if err != nil {
		_ = w.Close()
		s.reportError(rq, err.Error())
		return
	}
}

func (s *Server) writeError(w dns.ResponseWriter, rs *dns.Msg, code int) {
	rs.Rcode = code
	_ = w.WriteMsg(rs)
	_ = w.Close()
}

func (s *Server) reportError(r *dns.Msg, msg string) {
	if s.config.Reporter != nil {
		s.config.Reporter(fmt.Errorf("%s: %+v", msg, r))
	}
}
