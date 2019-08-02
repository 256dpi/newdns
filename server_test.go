package newdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

var awsNS = []string{
	"ns-1071.awsdns-05.org.",
	"ns-140.awsdns-17.com.",
	"ns-1978.awsdns-55.co.uk.",
	"ns-812.awsdns-37.net.",
}

const awsPrimaryNS = "ns-140.awsdns-17.com."

func TestAWSUDP(t *testing.T) {
	abstractTest(t, "udp", awsPrimaryNS+":53")
}

func TestServerUDP(t *testing.T) {
	zone := &Zone{
		Name:             "newdns.256dpi.com.",
		MasterNameServer: awsPrimaryNS,
		AllNameServers: []string{
			awsNS[0],
			awsNS[1],
			awsNS[2],
			awsNS[3],
		},
		AdminEmail: "awsdns-hostmaster@amazon.com",
		Refresh:    2 * time.Hour,
		Retry:      15 * time.Minute,
		Expire:     336 * time.Hour,
		SOATTL:     15 * time.Minute,
		MinTTL:     24 * time.Hour,
		Handler: func(typ Type, name string) ([]Record, error) {
			return nil, nil
		},
	}

	server := NewServer(Config{
		Handler: func(name string) (*Zone, error) {
			if InZone("newdns.256dpi.com.", name) {
				return zone, nil
			}

			return nil, nil
		},
		Reporter: func(err error) {
			panic(err)
		},
	})

	addr := "0.0.0.0:53001"

	run(server, addr, func() {
		abstractTest(t, "udp", addr)
	})
}

func abstractTest(t *testing.T, proto, addr string) {
	t.Run("ApexSOA", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "SOA", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "newdns.256dpi.com.", Qtype: dns.TypeSOA, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.SOA{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeSOA,
						Class:    dns.ClassINET,
						Ttl:      900,
						Rdlength: 66,
					},
					Ns:      awsPrimaryNS,
					Mbox:    "awsdns-hostmaster.amazon.com.",
					Serial:  1,
					Refresh: 7200,
					Retry:   900,
					Expire:  1209600,
					Minttl:  86400,
				},
			},
			Ns: []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeNS,
						Class:    dns.ClassINET,
						Ttl:      172800,
						Rdlength: 23,
					},
					Ns: awsNS[0],
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeNS,
						Class:    dns.ClassINET,
						Ttl:      172800,
						Rdlength: 2,
					},
					Ns: awsNS[1],
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeNS,
						Class:    dns.ClassINET,
						Ttl:      172800,
						Rdlength: 25,
					},
					Ns: awsNS[2],
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeNS,
						Class:    dns.ClassINET,
						Ttl:      172800,
						Rdlength: 22,
					},
					Ns: awsNS[3],
				},
			},
		}, ret)
	})

	t.Run("ApexNS", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "NS", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "newdns.256dpi.com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeNS,
						Class:    dns.ClassINET,
						Ttl:      172800,
						Rdlength: 23,
					},
					Ns: awsNS[0],
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeNS,
						Class:    dns.ClassINET,
						Ttl:      172800,
						Rdlength: 19,
					},
					Ns: awsNS[1],
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeNS,
						Class:    dns.ClassINET,
						Ttl:      172800,
						Rdlength: 25,
					},
					Ns: awsNS[2],
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeNS,
						Class:    dns.ClassINET,
						Ttl:      172800,
						Rdlength: 22,
					},
					Ns: awsNS[3],
				},
			},
		}, ret)
	})

	t.Run("MissingA", func(t *testing.T) {
		ret, err := query(proto, addr, "missing.newdns.256dpi.com.", "A", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
				Rcode:         dns.RcodeNameError,
			},
			Question: []dns.Question{
				{Name: "missing.newdns.256dpi.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			Ns: []dns.RR{
				&dns.SOA{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeSOA,
						Class:    dns.ClassINET,
						Ttl:      900,
						Rdlength: 66,
					},
					Ns:      awsPrimaryNS,
					Mbox:    "awsdns-hostmaster.amazon.com.",
					Serial:  1,
					Refresh: 7200,
					Retry:   900,
					Expire:  1209600,
					Minttl:  86400,
				},
			},
		}, ret)
	})

	t.Run("MissingCNAME", func(t *testing.T) {
		ret, err := query(proto, addr, "missing.newdns.256dpi.com.", "CNAME", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
				Rcode:         dns.RcodeNameError,
			},
			Question: []dns.Question{
				{Name: "missing.newdns.256dpi.com.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET},
			},
			Ns: []dns.RR{
				&dns.SOA{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeSOA,
						Class:    dns.ClassINET,
						Ttl:      900,
						Rdlength: 66,
					},
					Ns:      awsPrimaryNS,
					Mbox:    "awsdns-hostmaster.amazon.com.",
					Serial:  1,
					Refresh: 7200,
					Retry:   900,
					Expire:  1209600,
					Minttl:  86400,
				},
			},
		}, ret)
	})
}
