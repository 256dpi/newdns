package newdns

import (
	"math"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// IsDomain returns whether the name is a valid domain and if requested also
// fully qualified.
func IsDomain(name string, fqdn bool) bool {
	_, ok := dns.IsDomainName(name)
	return ok && (!fqdn || fqdn && dns.IsFqdn(name))
}

// InZone returns whether the provided name is part of the provided zone. Will
// always return false if the provided domains are not valid.
func InZone(zone, name string) bool {
	// check domains
	if !IsDomain(zone, false) || !IsDomain(name, false) {
		return false
	}

	return dns.IsSubDomain(zone, name)
}

// TrimZone will remove the zone from the specified name.
func TrimZone(zone, name string) string {
	// return immediately if not in zone
	if !InZone(zone, name) {
		return name
	}

	// count zone labels
	count := dns.CountLabel(zone)

	// get segments
	labels := dns.SplitDomainName(name)

	// get new labels
	newLabels := labels[0 : len(labels)-count]

	// join name
	newName := strings.Join(newLabels, ".")

	return newName
}

// Query can be used to query a DNS server over the provided protocol on its
// address fot the specified name and type. The supplied function can be set to
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
		Timeout: 500 * time.Millisecond,
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

func emailToDomain(email string) string {
	// split on at
	parts := strings.Split(email, "@")

	// replace dots in username
	parts[0] = strings.ReplaceAll(parts[0], ".", "\\.")

	// join domain
	name := parts[0] + "." + parts[1]

	return dns.Fqdn(name)
}

func durationToTime(d time.Duration) uint32 {
	return uint32(math.Ceil(d.Seconds()))
}

func transferCase(source, destination string) string {
	// get lower variants
	lowSource := strings.ToLower(source)
	lowDestination := strings.ToLower(destination)

	// get index of destination in source
	index := strings.Index(lowSource, lowDestination)
	if index < 0 {
		return destination
	}

	// take shared part from source
	return source[index:]
}
