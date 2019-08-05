package newdns

import (
	"fmt"
	"sort"
	"time"
)

// Zone describes a single authoritative DNS zone.
type Zone struct {
	// The FQDN of the zone e.g. "example.com.".
	Name string

	// The FQDN of the master mame server responsible for this zone. The FQDN
	// must be returned as A and AAAA record by the parent zone.
	MasterNameServer string

	// A list of FQDNs to all authoritative name servers for this zone. The
	// FQDNs must be returned as A and AAAA records by the parent zone. It is
	// required to announce at least two distinct name servers per zone.
	AllNameServers []string

	// The email address of the administrator e.g. "hostmaster@example.com".
	//
	// Default: "hostmaster@NAME".
	AdminEmail string

	// The refresh interval.
	//
	// Default: 6h.
	Refresh time.Duration

	// The retry interval for the zone.
	//
	// Default: 1h.
	Retry time.Duration

	// The expiration interval of the zone.
	//
	// Default: 72h.
	Expire time.Duration

	// The TTl for the SOA record.
	//
	// Default: 15m.
	SOATTL time.Duration

	// The TTl for NS records.
	//
	// Default: 48h.
	NSTTL time.Duration

	// The minimum TTL for all records. Either this value, or the SOATTL if lower,
	// is used to determine the "negative caching TTL" which is the duration
	// caches are allowed to cache missing records (NXDOMAIN).
	//
	// Default: 5min.
	MinTTL time.Duration

	// The handler that responds to requests for this zone.
	Handler func(name string) ([]Set, error)
}

// Validate will validate the zone and ensure the documented defaults.
func (z *Zone) Validate() error {
	// check name
	if !IsDomain(z.Name, true) {
		return fmt.Errorf("name not fully qualified")
	}

	// check master name server
	if !IsDomain(z.MasterNameServer, true) {
		return fmt.Errorf("master server not full qualified")
	}

	// check name server count
	if len(z.AllNameServers) < 1 {
		return fmt.Errorf("missing name server")
	}

	// check name servers
	for _, ns := range z.AllNameServers {
		if !IsDomain(ns, true) {
			return fmt.Errorf("name server not fully qualified")
		}
	}

	// sort name servers
	sort.Strings(z.AllNameServers)

	// set default admin email
	if z.AdminEmail == "" {
		z.AdminEmail = fmt.Sprintf("hostmaster@%s", z.Name)
	}

	// check admin email
	if !IsDomain(emailToDomain(z.AdminEmail), true) {
		return fmt.Errorf("admin email cannot be converted to a domain name")
	}

	// set default refresh
	if z.Refresh == 0 {
		z.Refresh = 6 * time.Hour
	}

	// set default retry
	if z.Retry == 0 {
		z.Retry = time.Hour
	}

	// set default expire
	if z.Expire == 0 {
		z.Expire = 72 * time.Hour
	}

	// set default SOA TTL
	if z.SOATTL == 0 {
		z.SOATTL = 15 * time.Minute
	}

	// set default NS TTL
	if z.NSTTL == 0 {
		z.NSTTL = 48 * time.Hour
	}

	// set default min TTL
	if z.MinTTL == 0 {
		z.MinTTL = 5 * time.Minute
	}

	// check retry
	if z.Retry >= z.Refresh {
		return fmt.Errorf("retry must be less than refresh")
	}

	// check expire
	if z.Expire < z.Refresh+z.Retry {
		return fmt.Errorf("expire must be bigger than the sum of refresh and retry")
	}

	return nil
}

func (z *Zone) minTTL(ttl time.Duration) time.Duration {
	// return zone min ttl if to less
	if ttl < z.MinTTL {
		return z.MinTTL
	}

	return ttl
}
