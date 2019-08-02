package newdns

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func run(s *Server, addr string, fn func()) {
	defer s.Close()

	go func() {
		err := s.Run(addr)
		if err != nil {
			panic(err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	fn()
}

func query(proto, addr, name, typ string, edns bool) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   name,
		Qtype:  dns.StringToType[typ],
		Qclass: dns.ClassINET,
	}

	if edns {
		msg.SetEdns0(4096, false)
	}

	client := dns.Client{Net: proto}
	ret, _, err := client.Exchange(msg, addr)
	if err != nil {
		return nil, err
	}

	ret.Id = 0

	return ret, nil
}

func equalJSON(t *testing.T, a, b interface{}) {
	buf := new(bytes.Buffer)

	e := json.NewEncoder(buf)
	e.SetIndent("", "  ")

	_ = e.Encode(a)
	aa := buf.String()

	buf.Reset()
	_ = e.Encode(b)
	bb := buf.String()

	assert.JSONEq(t, aa, bb)
}
