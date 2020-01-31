package newdns

import (
	"time"

	"github.com/miekg/dns"
)

// Query can be used to query a DNS server over the provided protocol on its
// address for the specified name and type. The supplied function can be set to
// mutate the sent request.
func Query(proto, addr, name, typ string, fn func(*dns.Msg)) (*dns.Msg, error) {
	// prepare request
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   name,
		Qtype:  dns.StringToType[typ],
		Qclass: dns.ClassINET,
	}

	// call function if available
	if fn != nil {
		fn(msg)
	}

	// prepare client
	client := dns.Client{
		Net:     proto,
		Timeout: time.Second,
	}

	// send request
	ret, _, err := client.Exchange(msg, addr)
	if err != nil {
		return nil, err
	}

	// reset id to allow direct comparison
	ret.Id = 0

	return ret, nil
}
