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

	// The weight for SRV records.
	Weight int

	// The port for SRV records.
	Port int

	// The data for TXT records.
	Data []string
}

// Validate will validate the record.
func (r *Record) Validate(typ Type) error {
	// validate A address
	if typ == A {
		ip := net.ParseIP(r.Address)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid IPv4 address: %s", r.Address)
		}
	}

	// validate AAAA address
	if typ == AAAA {
		ip := net.ParseIP(r.Address)
		if ip == nil || ip.To16() == nil {
			return fmt.Errorf("invalid IPv6 address: %s", r.Address)
		}
	}

	// validate CNAME and MX addresses
	if typ == CNAME || typ == MX {
		if !IsDomain(r.Address, true) {
			return fmt.Errorf("invalid domain name: %s", r.Address)
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

	// validate NS addresses
	if typ == NS {
		if !IsDomain(r.Address, true) {
			return fmt.Errorf("invalid ns name: %s", r.Address)
		}
	}

	// validate SRV records
	if typ == SRV {
		if r.Priority < 0 || r.Priority > 65535 {
			return fmt.Errorf("invalid priority: %d", r.Priority)
		}

		if r.Weight < 0 || r.Weight > 65535 {
			return fmt.Errorf("invalid weight: %d", r.Weight)
		}

		if r.Port < 0 || r.Port > 65535 {
			return fmt.Errorf("invalid port: %d", r.Port)
		}
	}

	return nil
}
