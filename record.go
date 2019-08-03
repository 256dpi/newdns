package newdns

import (
	"fmt"
	"net"
	"sort"
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
	// The target address for A, AAAA, CNAME, MX and NS records.
	Address string

	// The priority for MX records.
	Priority int

	// The data for TXT records.
	Data []string
}

// Validate will validate the record.
func (r *Record) Validate(set *Set) error {
	// validate A and AAAA addresses
	if set.Type == TypeA || set.Type == TypeAAAA {
		if net.ParseIP(r.Address) == nil {
			return fmt.Errorf("invalid address")
		}
	}

	// validate CNAME and MX addresses
	if set.Type == TypeCNAME || set.Type == TypeMX {
		if !dns.IsFqdn(r.Address) {
			return fmt.Errorf("invalid address")
		}
	}

	// check txt data
	if set.Type == TypeTXT && len(r.Data) == 0 {
		return fmt.Errorf("missing txt data")
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

// Set is a set of records.
type Set struct {
	// The type of the record.
	Type Type

	// The records in the set.
	Records []Record

	// The TTl of the record.
	//
	// Default: 5m.
	TTL time.Duration
}

// Validate will validate the set and ensure defaults.
func (s *Set) Validate() error {
	// check type
	if !s.Type.valid() {
		return fmt.Errorf("invalid type")
	}

	// check records
	if len(s.Records) == 0 {
		return fmt.Errorf("missing records")
	}

	// validate records
	for _, record := range s.Records {
		err := record.Validate(s)
		if err != nil {
			return err
		}
	}

	// sort records
	sort.Slice(s.Records, func(i, j int) bool {
		return s.Records[i].sortKey() < s.Records[j].sortKey()
	})

	// set default ttl
	if s.TTL == 0 {
		s.TTL = 5 * time.Minute
	}

	return nil
}

func (s *Set) convert(zone *Zone, name string) []dns.RR {
	// prepare list
	var list []dns.RR

	// add records
	for _, record := range s.Records {
		list = append(list, record.convert(zone, s, name))
	}

	return list
}
