package newdns

import (
	"net"
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

func TestAWS(t *testing.T) {
	t.Run("UDP", func(t *testing.T) {
		abstractTest(t, "udp", awsPrimaryNS+":53")
	})

	t.Run("TCP", func(t *testing.T) {
		abstractTest(t, "tcp", awsPrimaryNS+":53")
	})
}

func TestServer(t *testing.T) {
	zone := &Zone{
		Name:             "newdns.256dpi.com.",
		MasterNameServer: awsPrimaryNS,
		AllNameServers: []string{
			awsNS[1],
			awsNS[0],
			awsNS[3],
			awsNS[2],
		},
		AdminEmail: "awsdns-hostmaster@amazon.com",
		Refresh:    2 * time.Hour,
		Retry:      15 * time.Minute,
		Expire:     336 * time.Hour,
		SOATTL:     15 * time.Minute,
		NSTTL:      48 * time.Hour,
		MinTTL:     5 * time.Minute,
		Handler: func(name string) ([]Set, error) {
			// handle apex records
			if name == "" {
				return []Set{
					{
						Type: TypeA,
						Records: []Record{
							{Address: "1.2.3.4"},
						},
					},
					{
						Type: TypeAAAA,
						Records: []Record{
							{Address: "1:2:3:4::"},
						},
					},
					{
						Type: TypeTXT,
						Records: []Record{
							{Data: []string{"foo", "bar"}},
							{Data: []string{"baz"}},
						},
					},
				}, nil
			}

			// handle example
			if name == "example" {
				return []Set{
					{
						Type: TypeCNAME,
						Records: []Record{
							{Address: "example.com."},
						},
					},
				}, nil
			}

			// handle ip4
			if name == "ip4" {
				return []Set{
					{
						Type: TypeA,
						Records: []Record{
							{Address: "1.2.3.4"},
						},
					},
				}, nil
			}

			// handle ip6
			if name == "ip6" {
				return []Set{
					{
						Type: TypeAAAA,
						Records: []Record{
							{Address: "1:2:3:4::"},
						},
					},
				}, nil
			}

			// handle mail
			if name == "mail" {
				return []Set{
					{
						Type: TypeMX,
						Records: []Record{
							{Address: "mail.example.com.", Priority: 7},
						},
					},
				}, nil
			}

			// handle text
			if name == "text" {
				return []Set{
					{
						Type: TypeTXT,
						Records: []Record{
							{Data: []string{"foo", "bar"}},
						},
					},
				}, nil
			}

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
	})

	addr := "0.0.0.0:53001"

	run(server, addr, func() {
		t.Run("UDP", func(t *testing.T) {
			abstractTest(t, "udp", addr)
		})

		t.Run("TCP", func(t *testing.T) {
			abstractTest(t, "tcp", addr)
		})
	})
}

func abstractTest(t *testing.T, proto, addr string) {
	t.Run("ApexA", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "A", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "newdns.256dpi.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeA,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 4,
					},
					A: net.ParseIP("1.2.3.4"),
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

	t.Run("ApexAAAA", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "AAAA", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "newdns.256dpi.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.AAAA{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeAAAA,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 16,
					},
					AAAA: net.ParseIP("1:2:3:4::"),
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

	t.Run("ApexCNAME", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "CNAME", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
				Rcode:         dns.RcodeSuccess,
			},
			Question: []dns.Question{
				{Name: "newdns.256dpi.com.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET},
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
					Minttl:  300,
				},
			},
		}, ret)
	})

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
					Minttl:  300,
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

	t.Run("ApexTXT", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "TXT", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "newdns.256dpi.com.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.TXT{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeTXT,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 4,
					},
					Txt: []string{"baz"},
				},
				&dns.TXT{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeTXT,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 8,
					},
					Txt: []string{"foo", "bar"},
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

	t.Run("SubA", func(t *testing.T) {
		ret, err := query(proto, addr, "ip4.newdns.256dpi.com.", "A", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "ip4.newdns.256dpi.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:     "ip4.newdns.256dpi.com.",
						Rrtype:   dns.TypeA,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 4,
					},
					A: net.ParseIP("1.2.3.4"),
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

	t.Run("SubAAAA", func(t *testing.T) {
		ret, err := query(proto, addr, "ip6.newdns.256dpi.com.", "AAAA", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "ip6.newdns.256dpi.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.AAAA{
					Hdr: dns.RR_Header{
						Name:     "ip6.newdns.256dpi.com.",
						Rrtype:   dns.TypeAAAA,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 16,
					},
					AAAA: net.ParseIP("1:2:3:4::"),
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

	t.Run("SubCNAME", func(t *testing.T) {
		ret, err := query(proto, addr, "example.newdns.256dpi.com.", "CNAME", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "example.newdns.256dpi.com.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:     "example.newdns.256dpi.com.",
						Rrtype:   dns.TypeCNAME,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 10,
					},
					Target: "example.com.",
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

	t.Run("SubMX", func(t *testing.T) {
		ret, err := query(proto, addr, "mail.newdns.256dpi.com.", "MX", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "mail.newdns.256dpi.com.", Qtype: dns.TypeMX, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.MX{
					Hdr: dns.RR_Header{
						Name:     "mail.newdns.256dpi.com.",
						Rrtype:   dns.TypeMX,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 17,
					},
					Mx:         "mail.example.com.",
					Preference: 7,
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

	t.Run("SubTXT", func(t *testing.T) {
		ret, err := query(proto, addr, "text.newdns.256dpi.com.", "TXT", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "text.newdns.256dpi.com.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.TXT{
					Hdr: dns.RR_Header{
						Name:     "text.newdns.256dpi.com.",
						Rrtype:   dns.TypeTXT,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 8,
					},
					Txt: []string{"foo", "bar"},
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

	t.Run("SubCNAMEForA", func(t *testing.T) {
		ret, err := query(proto, addr, "example.newdns.256dpi.com.", "A", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "example.newdns.256dpi.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:     "example.newdns.256dpi.com.",
						Rrtype:   dns.TypeCNAME,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 10,
					},
					Target: "example.com.",
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

	t.Run("SubCNAMEForAAAA", func(t *testing.T) {
		ret, err := query(proto, addr, "example.newdns.256dpi.com.", "AAAA", false)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "example.newdns.256dpi.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:     "example.newdns.256dpi.com.",
						Rrtype:   dns.TypeCNAME,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 10,
					},
					Target: "example.com.",
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

	t.Run("NoExactRecord", func(t *testing.T) {
		assertMissing(t, proto, addr, "ip4.newdns.256dpi.com.", "CNAME", dns.RcodeSuccess)
		assertMissing(t, proto, addr, "ip6.newdns.256dpi.com.", "CNAME", dns.RcodeSuccess)
		assertMissing(t, proto, addr, "ip4.newdns.256dpi.com.", "AAAA", dns.RcodeSuccess)
		assertMissing(t, proto, addr, "ip6.newdns.256dpi.com.", "A", dns.RcodeSuccess)
		assertMissing(t, proto, addr, "mail.newdns.256dpi.com.", "A", dns.RcodeSuccess)
		assertMissing(t, proto, addr, "text.newdns.256dpi.com.", "A", dns.RcodeSuccess)
	})

	t.Run("MissingRecords", func(t *testing.T) {
		assertMissing(t, proto, addr, "missing.newdns.256dpi.com.", "A", dns.RcodeNameError)
		assertMissing(t, proto, addr, "missing.newdns.256dpi.com.", "AAAA", dns.RcodeNameError)
		assertMissing(t, proto, addr, "missing.newdns.256dpi.com.", "CNAME", dns.RcodeNameError)
		assertMissing(t, proto, addr, "missing.newdns.256dpi.com.", "MX", dns.RcodeNameError)
		assertMissing(t, proto, addr, "missing.newdns.256dpi.com.", "TXT", dns.RcodeNameError)
	})
}

func assertMissing(t *testing.T, proto, addr, name, typ string, code int) {
	qt := dns.StringToType[typ]

	ret, err := query(proto, addr, name, typ, false)
	assert.NoError(t, err)
	equalJSON(t, &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response:      true,
			Authoritative: true,
			Rcode:         code,
		},
		Question: []dns.Question{
			{Name: name, Qtype: qt, Qclass: dns.ClassINET},
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
				Minttl:  300,
			},
		},
	}, ret)
}
