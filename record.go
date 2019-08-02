package newdns

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Type denotes the DNS record type.
type Type uint16

const (
	// A records return IPV4 addresses.
	TypeA = Type(dns.TypeA)

	// AAAA records return IPV6 addresses.
	TypeAAAA = Type(dns.TypeAAAA)

	// CNAME records return other DNS names.
	TypeCNAME = Type(dns.TypeCNAME)

	// MX records return mails servers with their priorities.
	TypeMX = Type(dns.TypeMX)

	// TXT records return arbitrary text data.
	TypeTXT = Type(dns.TypeTXT)
)

// Strings returns the name of the type.
func (t Type) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeAAAA:
		return "AAAA"
	case TypeCNAME:
		return "CNAME"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	default:
		return ""
	}
}

func (t Type) valid() bool {
	switch t {
	case TypeA, TypeAAAA, TypeCNAME, TypeMX, TypeTXT:
		return true
	default:
		return false
	}
}

// Record holds a single DNS record.
type Record struct {
	// The type of the record.
	Type Type

	// The target address for A, AAAA, CNAME, MX and NS records.
	Address string

	// The TTl of the record.
	//
	// Default: 5m.
	TTL time.Duration

	// The priority for MX records.
	MXPriority int

	// The data of TXT records.
	TXTData []string
}

// Validate will validate the record and ensure defaults.
func (r *Record) Validate() error {
	// check type
	if !r.Type.valid() {
		return fmt.Errorf("invalid type")
	}

	// TODO: Check address.

	// set default ttl
	if r.TTL == 0 {
		r.TTL = 5 * time.Minute
	}

	return nil
}

func (r *Record) convert(name string, zone *Zone) dns.RR {
	// prepare header
	header := dns.RR_Header{
		Name:   name,
		Rrtype: uint16(r.Type),
		Class:  dns.ClassINET,
		Ttl:    durationToTime(zone.minTTL(r.TTL)),
	}

	// construct record
	switch r.Type {
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
			Preference: uint16(r.MXPriority),
			Mx:         dns.Fqdn(r.Address),
		}
	case TypeTXT:
		return &dns.TXT{
			Hdr: header,
			Txt: r.TXTData,
		}
	default:
		return nil
	}
}
