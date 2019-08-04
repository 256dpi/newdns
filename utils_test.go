package newdns

import (
	"bytes"
	"encoding/json"
	"strings"
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

func query(proto, addr, name, typ string, fn func(*dns.Msg)) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   name,
		Qtype:  dns.StringToType[typ],
		Qclass: dns.ClassINET,
	}

	if fn != nil {
		fn(msg)
	}

	client := dns.Client{
		Net:     proto,
		Timeout: 500 * time.Millisecond,
	}

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

func isIOError(err error) bool {
	if err == nil {
		return false
	}

	if strings.Contains(err.Error(), "i/o timeout") {
		return true
	}

	if strings.Contains(err.Error(), "connection reset by peer") {
		return true
	}

	return false
}
