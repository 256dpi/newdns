package newdns

import "github.com/miekg/dns"

// Type denotes the DNS record type.
type Type uint16

const (
	// A records return IPV4 addresses.
	TypeA = Type(dns.TypeA)

	// AAAA records return IPV6 addresses.
	TypeAAAA = Type(dns.TypeAAAA)

	// CNAME records return other DNS names.
	TypeCNAME = Type(dns.TypeCNAME)

	// MX records return mails servers with their priorities. The target mail
	// servers must itself be returned with an A or AAAA record.
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
