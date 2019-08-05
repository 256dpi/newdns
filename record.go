package newdns

import (
	"fmt"
	"net"
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
	if typ == A {
		ip := net.ParseIP(r.Address)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid IPv4 address")
		}
	}

	// validate AAAA address
	if typ == AAAA {
		ip := net.ParseIP(r.Address)
		if ip == nil || ip.To16() == nil {
			return fmt.Errorf("invalid IPv6 address")
		}
	}

	// validate CNAME and MX addresses
	if typ == CNAME || typ == MX {
		if !IsDomain(r.Address, true) {
			return fmt.Errorf("invalid domain address")
		}
	}

	// check TXT data
	if typ == TXT {
		if len(r.Data) == 0 {
			return fmt.Errorf("missing data")
		}

		for _, data := range r.Data {
			if len(data) > 255 {
				return fmt.Errorf("data too long")
			}
		}
	}

	return nil
}

func (r *Record) sortKey(typ Type) string {
	switch typ {
	case A, AAAA, CNAME:
		return r.Address
	case MX:
		return fmt.Sprintf("%020d %s", r.Priority, r.Address)
	case TXT:
		return r.Data[0]
	default:
		return ""
	}
}
