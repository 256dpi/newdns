package newdns

import (
	"math"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// InZone returns whether the provided name is part of the provided zone.
func InZone(zone, name string) bool {
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
