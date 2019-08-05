package newdns

import (
	"fmt"
	"sort"
	"time"
)

// Set is a set of records.
type Set struct {
	// The FQDN of the set.
	Name string

	// The type of the record.
	Type Type

	// The records in the set.
	Records []Record

	// The TTL of the set.
	//
	// Default: 5m.
	TTL time.Duration
}

// Validate will validate the set and ensure defaults.
func (s *Set) Validate(zone string) error {
	// check name
	if !IsDomain(s.Name, true) {
		return fmt.Errorf("invalid name")
	}

	// check relationship
	if !InZone(zone, s.Name) {
		return fmt.Errorf("name does not belong to zone")
	}

	// check type
	if !s.Type.valid() {
		return fmt.Errorf("invalid type")
	}

	// check records
	if len(s.Records) == 0 {
		return fmt.Errorf("missing records")
	}

	// check CNAME records
	if s.Type == TypeCNAME && len(s.Records) > 1 {
		return fmt.Errorf("multiple CNAME records")
	}

	// validate records
	for _, record := range s.Records {
		err := record.Validate(s.Type)
		if err != nil {
			return err
		}
	}

	// sort records
	sort.Slice(s.Records, func(i, j int) bool {
		return s.Records[i].sortKey(s.Type) < s.Records[j].sortKey(s.Type)
	})

	// set default ttl
	if s.TTL == 0 {
		s.TTL = 5 * time.Minute
	}

	return nil
}
