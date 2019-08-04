package newdns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// Record holds a single DNS record.
type Record struct {
	// The target address for A, AAAA, CNAME and MX records.
	Address string

	// The priority for MX records.
	Priority int

	// The data for TXT records.
	Data []string
}

// Validate will validate the record.
func (r *Record) Validate(typ Type) error {
	// validate A address
	if typ == TypeA {
		ip := net.ParseIP(r.Address)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid IPv4 address")
		}
	}

	// validate  AAAA address
	if typ == TypeAAAA {
		ip := net.ParseIP(r.Address)
		if ip == nil || ip.To16() == nil {
			return fmt.Errorf("invalid IPv6 address")
		}
	}

	// validate CNAME and MX addresses
	if typ == TypeCNAME || typ == TypeMX {
		if !IsDomain(r.Address, true) {
			return fmt.Errorf("invalid domain address")
		}
	}

	// check txt data
	if typ == TypeTXT && len(r.Data) == 0 {
		return fmt.Errorf("missing data")
	}

	return nil
}

func (r *Record) convert(zone *Zone, set *Set, name string) dns.RR {
	// prepare header
	header := dns.RR_Header{
		Name:   name,
		Rrtype: uint16(set.Type),
		Class:  dns.ClassINET,
		Ttl:    durationToTime(zone.minTTL(set.TTL)),
	}

	// construct record
	switch set.Type {
	case TypeA:
		return &dns.A{
			Hdr: header,
			A:   net.ParseIP(r.Address),
		}
	case TypeAAAA:
		return &dns.AAAA{
			Hdr:  header,
			AAAA: net.ParseIP(r.Address),
		}
	case TypeCNAME:
		return &dns.CNAME{
			Hdr:    header,
			Target: dns.Fqdn(r.Address),
		}
	case TypeMX:
		return &dns.MX{
			Hdr:        header,
			Preference: uint16(r.Priority),
			Mx:         dns.Fqdn(r.Address),
		}
	case TypeTXT:
		return &dns.TXT{
			Hdr: header,
			Txt: r.Data,
		}
	default:
		return nil
	}
}

func (r *Record) sortKey() string {
	// return address if set
	if r.Address != "" {
		return r.Address
	}

	// return firs txt data
	if len(r.Data) > 0 {
		return r.Data[0]
	}

	return ""
}
