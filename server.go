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
	if int(dh.Bits>>11) & 0xF != dns.OpcodeQuery  {
		return dns.MsgIgnore
	}

	// check question count
	if dh.Qdcount != 1 {
		return dns.MsgReject
	}

	// check answer and authoritative records
	if dh.Ancount > 0 || dh.Nscount > 0 {
		return dns.MsgReject
	}

	// check additional records
	if dh.Arcount > 2 {
		return dns.MsgReject
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
		// check version
		if rq.IsEdns0().Version() != 0 {
			s.writeError(w, rs, dns.RcodeBadVers)
			s.reportError(rq, "invalid edns version")
			return
		}

		// use edns in reply
		rs.SetEdns0(uint16(s.config.BufferSize), false)
	}

	// get question
	question := rq.Question[0]

	// check class
	if question.Qclass != dns.ClassINET {
		// leave connection hanging
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

	// lookup main record
	result, handled := s.lookup(w, rq, rs, zone, name, question.Qtype)
	if handled {
		return
	}

	// set answer
	rs.Answer = result

	// check answers
	for _, answer := range rs.Answer {
		switch record := answer.(type) {
		case *dns.MX:
			// lookup internal MX targets
			if InZone(zone.Name, record.Mx) {
				result, handled := s.lookup(w, rq, rs, zone, record.Mx, dns.TypeA)
				if handled {
					return
				}

				// add results to extra
				rs.Extra = append(rs.Extra, result...)
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

func (s *Server) lookup(w dns.ResponseWriter, rq, rs *dns.Msg, zone *Zone, name string, needle uint16) ([]dns.RR, bool) {
	// prepare answer
	var answer []dns.RR

	// retrieve sets for zone
	for i := 0; ; i++ {
		// get sets
		sets, err := zone.Handler(TrimZone(zone.Name, name))
		if err != nil {
			s.writeError(w, rs, dns.RcodeServerFailure)
			s.reportError(rq, err.Error())
			return nil, true
		}

		// return error if initial set is empty
		if i == 0 && len(sets) == 0 {
			s.writeErrorWithSOA(w, rq, rs, zone, dns.RcodeNameError)
			return nil, true
		}

		// prepare counters
		counters := map[Type]int{
			TypeA:     0,
			TypeAAAA:  0,
			TypeCNAME: 0,
			TypeMX:    0,
			TypeTXT:   0,
		}

		// validate sets
		for _, set := range sets {
			// validate set
			err = set.Validate()
			if err != nil {
				s.writeError(w, rs, dns.RcodeServerFailure)
				s.reportError(rq, err.Error())
				return nil, true
			}

			// increment counter
			counters[set.Type] = counters[set.Type] + 1
		}

		// check counters
		for _, counter := range counters {
			if counter > 1 {
				s.writeError(w, rs, dns.RcodeServerFailure)
				s.reportError(rq, "multiple sets for same type")
				return nil, true
			}
		}

		// check apex CNAME
		if counters[TypeCNAME] > 0 && name == zone.Name {
			s.writeError(w, rs, dns.RcodeServerFailure)
			s.reportError(rq, "invalid CNAME at apex")
			return nil, true
		}

		// check CNAME is stand-alone
		if counters[TypeCNAME] > 0 && (len(sets) > 1) {
			s.writeError(w, rs, dns.RcodeServerFailure)
			s.reportError(rq, "a CNAME set must be stand-alone")
			return nil, true
		}

		// check if CNAME and query is not CNAME
		if counters[TypeCNAME] > 0 && needle != dns.TypeCNAME {
			// add CNAME set to answer
			answer = append(answer, sets[0].convert(zone, name)...)

			// continue with CNAME address if address is in zone
			if InZone(zone.Name, sets[0].Records[0].Address) {
				name = sets[0].Records[0].Address
				continue
			}

			// otherwise break
			break
		}

		// add matching set
		for _, set := range sets {
			if uint16(set.Type) == needle {
				// add records
				answer = append(answer, set.convert(zone, name)...)

				break
			}
		}

		// write SOA with success code to indicate availability of other sets
		if len(answer) == 0 {
			s.writeErrorWithSOA(w, rq, rs, zone, dns.RcodeSuccess)
			return nil, true
		}

		break
	}

	return answer, false
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
