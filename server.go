package newdns

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Config provides configuration for a DNS server.
type Config struct {
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

func (s *Server) handler(w dns.ResponseWriter, r *dns.Msg) {
	// check opcode
	if r.Opcode != dns.OpcodeQuery {
		s.writeErr(w, r, dns.RcodeNotImplemented)
		s.reportErr(r, "opcode is not query")
		return
	}

	// ignore to less or too many questions
	if len(r.Question) != 1 {
		s.writeErr(w, r, dns.RcodeNotImplemented)
		s.reportErr(r, "too many questions")
		return
	}

	// get question
	question := r.Question[0]

	// check class
	if question.Qclass != dns.ClassINET {
		s.writeErr(w, r, dns.RcodeNotImplemented)
		s.reportErr(r, "unsupported question class")
		return
	}

	// get name
	name := strings.ToLower(dns.Name(question.Name).String())

	// get zone
	zone, err := s.config.Handler(name)
	if err != nil {
		s.writeErr(w, r, dns.RcodeServerFailure)
		s.reportErr(r, err.Error())
		return
	}

	// check zone
	if zone == nil {
		s.writeErr(w, r, dns.RcodeNameError)
		return
	}

	// validate zone
	err = zone.Validate()
	if err != nil {
		s.writeErr(w, r, dns.RcodeServerFailure)
		s.reportErr(r, err.Error())
		return
	}

	// answer SOA directly
	if question.Qtype == dns.TypeSOA && name == zone.Name {
		s.writeSOAResponse(w, r, zone)
		return
	}

	// answer NS directly
	if question.Qtype == dns.TypeNS && name == zone.Name {
		s.writeNSResponse(w, r, zone)
		return
	}

	// get records
	records, err := zone.Handler(TrimZone(zone.Name, name))
	if err != nil {
		s.writeErr(w, r, dns.RcodeServerFailure)
		s.reportErr(r, err.Error())
		return
	}

	// check records
	if len(records) == 0 {
		s.writeNameError(w, r, zone)
		return
	}

	// prepare response
	response := new(dns.Msg)
	response.SetReply(r)

	// always compress responses
	response.Compress = true

	// set flag
	response.Authoritative = true

	// add matching records
	for _, record := range records {
		// validate record
		err = record.Validate()
		if err != nil {
			s.writeErr(w, r, dns.RcodeServerFailure)
			s.reportErr(r, err.Error())
			return
		}

		// add matching answer
		if uint16(record.Type) == question.Qtype {
			response.Answer = append(response.Answer, record.convert(name, zone))
		}
	}

	// add ns records
	for _, ns := range zone.AllNameServers {
		response.Ns = append(response.Ns, &dns.NS{
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
	err = w.WriteMsg(response)
	if err != nil {
		s.reportErr(r, err.Error())
		return
	}
}

func (s *Server) writeSOAResponse(w dns.ResponseWriter, r *dns.Msg, zone *Zone) {
	// prepare response
	response := new(dns.Msg)
	response.SetReply(r)

	// always compress responses
	response.Compress = true

	// add soa record
	response.Answer = append(response.Answer, &dns.SOA{
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
		response.Ns = append(response.Ns, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   zone.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    durationToTime(zone.NSTTL),
			},
			Ns: ns,
		})
	}

	// set flag
	response.Authoritative = true

	// write message
	err := w.WriteMsg(response)
	if err != nil {
		s.reportErr(r, err.Error())
		return
	}
}

func (s *Server) writeNSResponse(w dns.ResponseWriter, r *dns.Msg, zone *Zone) {
	// prepare response
	response := new(dns.Msg)
	response.SetReply(r)

	// always compress responses
	response.Compress = true

	// set flag
	response.Authoritative = true

	// add ns records
	for _, ns := range zone.AllNameServers {
		response.Answer = append(response.Answer, &dns.NS{
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
	err := w.WriteMsg(response)
	if err != nil {
		s.reportErr(r, err.Error())
		return
	}
}

func (s *Server) writeNameError(w dns.ResponseWriter, r *dns.Msg, zone *Zone) {
	// prepare response
	response := new(dns.Msg)
	response.SetRcode(r, dns.RcodeNameError)

	// always compress responses
	response.Compress = true

	// add soa record
	response.Ns = append(response.Ns, &dns.SOA{
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

	// set flag
	response.Authoritative = true

	// write message
	err := w.WriteMsg(response)
	if err != nil {
		s.reportErr(r, err.Error())
		return
	}
}

func (s *Server) writeErr(w dns.ResponseWriter, r *dns.Msg, rCode int) {
	m := new(dns.Msg)
	m.SetRcode(r, rCode)
	m.SetRcodeFormatError(r)
	_ = w.WriteMsg(m)
}

func (s *Server) reportErr(r *dns.Msg, msg string) {
	if s.config.Reporter != nil {
		s.config.Reporter(fmt.Errorf("%s: %+v", msg, r))
	}
}

func durationToTime(d time.Duration) uint32 {
	return uint32(math.Ceil(d.Seconds()))
}
