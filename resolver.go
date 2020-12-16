package newdns

import (
	"net"

	"github.com/miekg/dns"
)

type responseWriter struct {
	msg *dns.Msg
}

func (w *responseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IP{0, 0, 0, 0},
		Port: 0,
	}
}

func (w *responseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IP{0, 0, 0, 0},
		Port: 0,
	}
}

func (w *responseWriter) WriteMsg(msg *dns.Msg) error {
	if w.msg != nil {
		panic("message already set")
	}
	w.msg = msg
	return nil
}

func (w *responseWriter) Write(buf []byte) (int, error) {
	panic("not implemented")
}

func (w *responseWriter) Close() error {
	return nil
}

func (w *responseWriter) TsigStatus() error {
	panic("not implemented")
}

func (w *responseWriter) TsigTimersOnly(bool) {
	panic("not implemented")
}

func (w *responseWriter) Hijack() {
	panic("not implemented")
}

// Resolver returns a very basic recursive resolver that uses the provided
// handler to resolve all names.
func Resolver(handler dns.Handler) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, rq *dns.Msg) {
		// handle non recursion
		if !rq.RecursionDesired {
			handler.ServeDNS(w, rq)
			return
		}

		// prepare response
		rs := new(dns.Msg)
		rs.SetReply(rq)
		rs.RecursionAvailable = true

		// prepare writer
		var wr responseWriter

		// forward request to fallback
		handler.ServeDNS(&wr, rq)

		// check response
		if wr.msg == nil {
			_ = w.WriteMsg(rs)
			return
		}

		// resolve and add answers
		rs.Answer = append(rs.Answer, resolveRecursive(handler, wr.msg.Answer)...)

		// write response
		err := w.WriteMsg(rs)
		if err != nil {
			_ = w.Close()
		}
	})
}

func resolveRecursive(handler dns.Handler, in []dns.RR) []dns.RR {
	// prepare result
	var out []dns.RR
	out = append(out, in...)

	// handle answers
	for _, answer := range in {
		if cname, ok := answer.(*dns.CNAME); ok {
			// prepare writer
			var wr responseWriter

			// serve query
			handler.ServeDNS(&wr, &dns.Msg{
				Question: []dns.Question{
					{
						Name:   cname.Target,
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					},
				},
			})

			// resolve and add answers
			out = append(out, resolveRecursive(handler, wr.msg.Answer)...)
		}
	}

	return out
}
