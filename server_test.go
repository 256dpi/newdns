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

var nsRRs = []dns.RR{
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
}

func TestAWS(t *testing.T) {
	t.Run("UDP", func(t *testing.T) {
		conformanceTests(t, "udp", awsPrimaryNS+":53")
	})

	t.Run("TCP", func(t *testing.T) {
		conformanceTests(t, "tcp", awsPrimaryNS+":53")
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

			// handle ref4
			if name == "ref4" {
				return []Set{
					{
						Type: TypeCNAME,
						Records: []Record{
							{Address: "ip4.newdns.256dpi.com."},
						},
					},
				}, nil
			}

			// handle ref6
			if name == "ref6" {
				return []Set{
					{
						Type: TypeCNAME,
						Records: []Record{
							{Address: "ip6.newdns.256dpi.com."},
						},
					},
				}, nil
			}

			// handle refref
			if name == "refref" {
				return []Set{
					{
						Type: TypeCNAME,
						Records: []Record{
							{Address: "ref4.newdns.256dpi.com."},
						},
					},
				}, nil
			}

			// handle ref4m
			if name == "ref4m" {
				return []Set{
					{
						Type: TypeMX,
						Records: []Record{
							{Address: "ip4.newdns.256dpi.com.", Priority: 7},
						},
					},
				}, nil
			}

			// handle ref6m
			if name == "ref6m" {
				return []Set{
					{
						Type: TypeMX,
						Records: []Record{
							{Address: "ip6.newdns.256dpi.com.", Priority: 7},
						},
					},
				}, nil
			}

			// handle long
			if name == "long" {
				return []Set{
					{
						Type: TypeTXT,
						Records: []Record{
							{Data: []string{"z4e6ycRMp6MP3WvWQMxIAOXglxANbj3oB0xD8BffktO4eo3VCR0s6TyGHKixvarOFJU0fqNkXeFOeI7sTXH5X0iXZukfLgnGTxLXNC7KkVFwtVFsh1P0IUNXtNBlOVWrVbxkS62ezbLpENNkiBwbkCvcTjwF2kyI0curAt9JhhJFb3AAq0q1iHWlJLn1KSrev9PIsY3alndDKjYTPxAojxzGKdK3A7rWLJ8Uzb3Z5OhLwP7jTKqbWVUocJRFLYp"}},
							{Data: []string{"gyK4oL9X8Zn3b6TwmUIYAgQx43rBOWMqJWR3wGMGNaZgajnhd2u9JaIbGwNo6gzZunyKYRxID3mKLmYUCcIrNYuo8R4UkijZeshwqEAM2EWnjNsB1hJHOlu6VyRKW13rsFUJedOSqc7YjjUoxm9c3mF28tEXmc3GVsC476wJ2ciSbp7ujDjQ032SQRD6kpayzFX8GncS5KXP8mLK2ZIqK2U4fUmYEpTPQMmp7w24GKkfGJzE4JfMBxSybDUScLq"}},
							{Data: []string{"upNh05zi9flqN2puI9eIGgAgl3gwc65l3WjFdnE3u55dhyUyIoKbOlc1mQJPULPkn1V5TTG9rLBB8AzNfeL8jvwO8h0mzmJhPH8n6dkgI546jB8Z0g0MRJxN5VNSixjFjdR8vtUp6EWlVi7QSe9SYInghV0M17zZ8mXSHwTfYZaPH54ng22mSWzVbRX2tlUPLTNRB5CHrEtxliyhhQlRey98P5G0eo35FUXdqzOSJ3HGqDssBWQAxK3I9feOjbE"}},
						},
					},
				}, nil
			}

			return nil, nil
		},
	}

	server := NewServer(Config{
		BufferSize: 4096,
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
		t.Run("UDP", func(t *testing.T) {
			conformanceTests(t, "udp", addr)
			additionalTests(t, "udp", addr)
		})

		t.Run("TCP", func(t *testing.T) {
			conformanceTests(t, "tcp", addr)
			additionalTests(t, "tcp", addr)
		})
	})
}

func conformanceTests(t *testing.T, proto, addr string) {
	t.Run("ApexA", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "A", nil)
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("ApexAAAA", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "AAAA", nil)
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("ApexCNAME", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "CNAME", nil)
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
		ret, err := query(proto, addr, "newdns.256dpi.com.", "SOA", nil)
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
		ret, err := query(proto, addr, "newdns.256dpi.com.", "NS", nil)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "newdns.256dpi.com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET},
			},
			Answer: nsRRs,
		}, ret)
	})

	t.Run("ApexTXT", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "TXT", nil)
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubA", func(t *testing.T) {
		ret, err := query(proto, addr, "ip4.newdns.256dpi.com.", "A", nil)
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubAAAA", func(t *testing.T) {
		ret, err := query(proto, addr, "ip6.newdns.256dpi.com.", "AAAA", nil)
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubCNAME", func(t *testing.T) {
		ret, err := query(proto, addr, "example.newdns.256dpi.com.", "CNAME", nil)
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubMX", func(t *testing.T) {
		ret, err := query(proto, addr, "mail.newdns.256dpi.com.", "MX", nil)
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubTXT", func(t *testing.T) {
		ret, err := query(proto, addr, "text.newdns.256dpi.com.", "TXT", nil)
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubCNAMEForA", func(t *testing.T) {
		ret, err := query(proto, addr, "example.newdns.256dpi.com.", "A", nil)
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubCNAMEForAAAA", func(t *testing.T) {
		ret, err := query(proto, addr, "example.newdns.256dpi.com.", "AAAA", nil)
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubCNAMEForAWithA", func(t *testing.T) {
		ret, err := query(proto, addr, "ref4.newdns.256dpi.com.", "A", nil)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "ref4.newdns.256dpi.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:     "ref4.newdns.256dpi.com.",
						Rrtype:   dns.TypeCNAME,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 6,
					},
					Target: "ip4.newdns.256dpi.com.",
				},
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubCNAMEForAAAAWithAAAA", func(t *testing.T) {
		ret, err := query(proto, addr, "ref6.newdns.256dpi.com.", "AAAA", nil)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "ref6.newdns.256dpi.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:     "ref6.newdns.256dpi.com.",
						Rrtype:   dns.TypeCNAME,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 6,
					},
					Target: "ip6.newdns.256dpi.com.",
				},
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubCNAMEWithoutA", func(t *testing.T) {
		ret, err := query(proto, addr, "ref4.newdns.256dpi.com.", "CNAME", nil)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "ref4.newdns.256dpi.com.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:     "ref4.newdns.256dpi.com.",
						Rrtype:   dns.TypeCNAME,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 6,
					},
					Target: "ip4.newdns.256dpi.com.",
				},
			},
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubCNAMEWithoutAAAA", func(t *testing.T) {
		ret, err := query(proto, addr, "ref6.newdns.256dpi.com.", "CNAME", nil)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "ref6.newdns.256dpi.com.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:     "ref6.newdns.256dpi.com.",
						Rrtype:   dns.TypeCNAME,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 6,
					},
					Target: "ip6.newdns.256dpi.com.",
				},
			},
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubCNAMEForCNAMEForAWithA", func(t *testing.T) {
		ret, err := query(proto, addr, "refref.newdns.256dpi.com.", "A", nil)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "refref.newdns.256dpi.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:     "refref.newdns.256dpi.com.",
						Rrtype:   dns.TypeCNAME,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 7,
					},
					Target: "ref4.newdns.256dpi.com.",
				},
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:     "ref4.newdns.256dpi.com.",
						Rrtype:   dns.TypeCNAME,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 6,
					},
					Target: "ip4.newdns.256dpi.com.",
				},
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubMXWithExtraA", func(t *testing.T) {
		ret, err := query(proto, addr, "ref4m.newdns.256dpi.com.", "MX", nil)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "ref4m.newdns.256dpi.com.", Qtype: dns.TypeMX, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.MX{
					Hdr: dns.RR_Header{
						Name:     "ref4m.newdns.256dpi.com.",
						Rrtype:   dns.TypeMX,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 8,
					},
					Preference: 7,
					Mx:         "ip4.newdns.256dpi.com.",
				},
			},
			Extra: []dns.RR{
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("SubMXWithExtraAAAA", func(t *testing.T) {
		ret, err := query(proto, addr, "ref6m.newdns.256dpi.com.", "MX", nil)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "ref6m.newdns.256dpi.com.", Qtype: dns.TypeMX, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.MX{
					Hdr: dns.RR_Header{
						Name:     "ref6m.newdns.256dpi.com.",
						Rrtype:   dns.TypeMX,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 8,
					},
					Preference: 7,
					Mx:         "ip6.newdns.256dpi.com.",
				},
			},
			Extra: []dns.RR{
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
			Ns: nsRRs,
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

	t.Run("NoExistingRecord", func(t *testing.T) {
		assertMissing(t, proto, addr, "missing.newdns.256dpi.com.", "A", dns.RcodeNameError)
		assertMissing(t, proto, addr, "missing.newdns.256dpi.com.", "AAAA", dns.RcodeNameError)
		assertMissing(t, proto, addr, "missing.newdns.256dpi.com.", "CNAME", dns.RcodeNameError)
		assertMissing(t, proto, addr, "missing.newdns.256dpi.com.", "MX", dns.RcodeNameError)
		assertMissing(t, proto, addr, "missing.newdns.256dpi.com.", "TXT", dns.RcodeNameError)
	})

	t.Run("TruncatedResponse", func(t *testing.T) {
		ret, err := query(proto, addr, "long.newdns.256dpi.com.", "TXT", nil)
		assert.NoError(t, err)

		if proto == "udp" {
			equalJSON(t, &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Response:      true,
					Authoritative: true,
					Truncated:     true,
				},
				Question: []dns.Question{
					{Name: "long.newdns.256dpi.com.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
				},
			}, ret)
		} else {
			equalJSON(t, &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Response:      true,
					Authoritative: true,
				},
				Question: []dns.Question{
					{Name: "long.newdns.256dpi.com.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
				},
				Answer: []dns.RR{
					&dns.TXT{
						Hdr: dns.RR_Header{
							Name:     "long.newdns.256dpi.com.",
							Rrtype:   dns.TypeTXT,
							Class:    dns.ClassINET,
							Ttl:      300,
							Rdlength: 256,
						},
						Txt: []string{
							"gyK4oL9X8Zn3b6TwmUIYAgQx43rBOWMqJWR3wGMGNaZgajnhd2u9JaIbGwNo6gzZunyKYRxID3mKLmYUCcIrNYuo8R4UkijZeshwqEAM2EWnjNsB1hJHOlu6VyRKW13rsFUJedOSqc7YjjUoxm9c3mF28tEXmc3GVsC476wJ2ciSbp7ujDjQ032SQRD6kpayzFX8GncS5KXP8mLK2ZIqK2U4fUmYEpTPQMmp7w24GKkfGJzE4JfMBxSybDUScLq",
						},
					},
					&dns.TXT{
						Hdr: dns.RR_Header{
							Name:     "long.newdns.256dpi.com.",
							Rrtype:   dns.TypeTXT,
							Class:    dns.ClassINET,
							Ttl:      300,
							Rdlength: 256,
						},
						Txt: []string{
							"upNh05zi9flqN2puI9eIGgAgl3gwc65l3WjFdnE3u55dhyUyIoKbOlc1mQJPULPkn1V5TTG9rLBB8AzNfeL8jvwO8h0mzmJhPH8n6dkgI546jB8Z0g0MRJxN5VNSixjFjdR8vtUp6EWlVi7QSe9SYInghV0M17zZ8mXSHwTfYZaPH54ng22mSWzVbRX2tlUPLTNRB5CHrEtxliyhhQlRey98P5G0eo35FUXdqzOSJ3HGqDssBWQAxK3I9feOjbE",
						},
					},
					&dns.TXT{
						Hdr: dns.RR_Header{
							Name:     "long.newdns.256dpi.com.",
							Rrtype:   dns.TypeTXT,
							Class:    dns.ClassINET,
							Ttl:      300,
							Rdlength: 256,
						},
						Txt: []string{
							"z4e6ycRMp6MP3WvWQMxIAOXglxANbj3oB0xD8BffktO4eo3VCR0s6TyGHKixvarOFJU0fqNkXeFOeI7sTXH5X0iXZukfLgnGTxLXNC7KkVFwtVFsh1P0IUNXtNBlOVWrVbxkS62ezbLpENNkiBwbkCvcTjwF2kyI0curAt9JhhJFb3AAq0q1iHWlJLn1KSrev9PIsY3alndDKjYTPxAojxzGKdK3A7rWLJ8Uzb3Z5OhLwP7jTKqbWVUocJRFLYp",
						},
					},
				},
				Ns: nsRRs,
			}, ret)
		}
	})

	t.Run("EDNSSuccess", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "A", func(msg *dns.Msg) {
			msg.SetEdns0(1337, false)
		})
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
			Ns: nsRRs,
			Extra: []dns.RR{
				&dns.OPT{
					Hdr: dns.RR_Header{
						Name:     ".",
						Rrtype:   dns.TypeOPT,
						Class:    4096,
						Ttl:      0,
						Rdlength: 0,
					},
				},
			},
		}, ret)
	})

	t.Run("EDNSError", func(t *testing.T) {
		ret, err := query(proto, addr, "missing.newdns.256dpi.com.", "A", func(msg *dns.Msg) {
			msg.SetEdns0(1337, false)
		})
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
					Minttl:  300,
				},
			},
			Extra: []dns.RR{
				&dns.OPT{
					Hdr: dns.RR_Header{
						Name:     ".",
						Rrtype:   dns.TypeOPT,
						Class:    4096,
						Ttl:      0,
						Rdlength: 0,
					},
				},
			},
		}, ret)
	})

	t.Run("EDNSBadVersion", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "A", func(msg *dns.Msg) {
			msg.SetEdns0(1337, false)
			msg.Extra[0].(*dns.OPT).SetVersion(2)
		})
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
				Rcode:         dns.RcodeBadVers,
			},
			Question: []dns.Question{
				{Name: "newdns.256dpi.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
			Extra: []dns.RR{
				&dns.OPT{
					Hdr: dns.RR_Header{
						Name:     ".",
						Rrtype:   dns.TypeOPT,
						Class:    4096,
						Ttl:      dns.RcodeBadVers << 20,
						Rdlength: 0,
					},
				},
			},
		}, ret)
	})

	t.Run("EDNSLongResponse", func(t *testing.T) {
		ret, err := query(proto, addr, "long.newdns.256dpi.com.", "TXT", func(msg *dns.Msg) {
			msg.SetEdns0(1337, false)
		})
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
			},
			Question: []dns.Question{
				{Name: "long.newdns.256dpi.com.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
			},
			Answer: []dns.RR{
				&dns.TXT{
					Hdr: dns.RR_Header{
						Name:     "long.newdns.256dpi.com.",
						Rrtype:   dns.TypeTXT,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 256,
					},
					Txt: []string{
						"gyK4oL9X8Zn3b6TwmUIYAgQx43rBOWMqJWR3wGMGNaZgajnhd2u9JaIbGwNo6gzZunyKYRxID3mKLmYUCcIrNYuo8R4UkijZeshwqEAM2EWnjNsB1hJHOlu6VyRKW13rsFUJedOSqc7YjjUoxm9c3mF28tEXmc3GVsC476wJ2ciSbp7ujDjQ032SQRD6kpayzFX8GncS5KXP8mLK2ZIqK2U4fUmYEpTPQMmp7w24GKkfGJzE4JfMBxSybDUScLq",
					},
				},
				&dns.TXT{
					Hdr: dns.RR_Header{
						Name:     "long.newdns.256dpi.com.",
						Rrtype:   dns.TypeTXT,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 256,
					},
					Txt: []string{
						"upNh05zi9flqN2puI9eIGgAgl3gwc65l3WjFdnE3u55dhyUyIoKbOlc1mQJPULPkn1V5TTG9rLBB8AzNfeL8jvwO8h0mzmJhPH8n6dkgI546jB8Z0g0MRJxN5VNSixjFjdR8vtUp6EWlVi7QSe9SYInghV0M17zZ8mXSHwTfYZaPH54ng22mSWzVbRX2tlUPLTNRB5CHrEtxliyhhQlRey98P5G0eo35FUXdqzOSJ3HGqDssBWQAxK3I9feOjbE",
					},
				},
				&dns.TXT{
					Hdr: dns.RR_Header{
						Name:     "long.newdns.256dpi.com.",
						Rrtype:   dns.TypeTXT,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 256,
					},
					Txt: []string{
						"z4e6ycRMp6MP3WvWQMxIAOXglxANbj3oB0xD8BffktO4eo3VCR0s6TyGHKixvarOFJU0fqNkXeFOeI7sTXH5X0iXZukfLgnGTxLXNC7KkVFwtVFsh1P0IUNXtNBlOVWrVbxkS62ezbLpENNkiBwbkCvcTjwF2kyI0curAt9JhhJFb3AAq0q1iHWlJLn1KSrev9PIsY3alndDKjYTPxAojxzGKdK3A7rWLJ8Uzb3Z5OhLwP7jTKqbWVUocJRFLYp",
					},
				},
			},
			Ns: nsRRs,
			Extra: []dns.RR{
				&dns.OPT{
					Hdr: dns.RR_Header{
						Name:     ".",
						Rrtype:   dns.TypeOPT,
						Class:    4096,
						Ttl:      0,
						Rdlength: 0,
					},
				},
			},
		}, ret)
	})

	t.Run("RecursionDesired", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "A", func(msg *dns.Msg) {
			msg.RecursionDesired = true
		})
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:         true,
				Authoritative:    true,
				RecursionDesired: true,
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("UnsupportedMessage", func(t *testing.T) {
		_, err := query(proto, addr, "newdns.256dpi.com.", "A", func(msg *dns.Msg) {
			msg.Response = true
		})
		assert.True(t, isIOError(err), err)
	})

	t.Run("UnsupportedOpcode", func(t *testing.T) {
		_, err := query(proto, addr, "newdns.256dpi.com.", "A", func(msg *dns.Msg) {
			msg.Opcode = dns.OpcodeNotify
		})
		assert.True(t, isIOError(err), err)
	})

	t.Run("UnsupportedClass", func(t *testing.T) {
		_, err := query(proto, addr, "newdns.256dpi.com.", "A", func(msg *dns.Msg) {
			msg.Question[0].Qclass = dns.ClassANY
		})
		assert.True(t, isIOError(err), err)
	})

	t.Run("IgnorePayload", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "A", func(msg *dns.Msg) {
			msg.Answer = []dns.RR{
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
				&dns.AAAA{
					Hdr: dns.RR_Header{
						Name:     "newdns.256dpi.com.",
						Rrtype:   dns.TypeAAAA,
						Class:    dns.ClassINET,
						Ttl:      300,
						Rdlength: 4,
					},
					AAAA: net.ParseIP("1:2:3:4::"),
				},
			}
			msg.Ns = []dns.RR{
				nsRRs[0],
			}
			msg.Extra = []dns.RR{
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
			}
		})
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
			Ns: nsRRs,
		}, ret)
	})

	t.Run("MultipleQuestions", func(t *testing.T) {
		_, err := query(proto, addr, "newdns.256dpi.com.", "A", func(msg *dns.Msg) {
			msg.Question = append(msg.Question, dns.Question{
				Name:   "newdns.256dpi.com.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			})
		})
		assert.True(t, isIOError(err), err)
	})

	t.Run("UnsupportedType", func(t *testing.T) {
		assertMissing(t, proto, addr, "missing.newdns.256dpi.com.", "NULL", dns.RcodeNameError)
	})

	t.Run("NonAuthoritativeZone", func(t *testing.T) {
		ret, err := query(proto, addr, "foo.256dpi.com.", "A", nil)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: false,
				Rcode:         dns.RcodeRefused,
			},
			Question: []dns.Question{
				{Name: "foo.256dpi.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		}, ret)
	})
}

func additionalTests(t *testing.T, proto, addr string) {
	t.Run("UnsupportedAny", func(t *testing.T) {
		ret, err := query(proto, addr, "newdns.256dpi.com.", "ANY", nil)
		assert.NoError(t, err)
		equalJSON(t, &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Response:      true,
				Authoritative: true,
				Rcode:         dns.RcodeNotImplemented,
			},
			Question: []dns.Question{
				{Name: "newdns.256dpi.com.", Qtype: dns.TypeANY, Qclass: dns.ClassINET},
			},
		}, ret)
	})
}

func assertMissing(t *testing.T, proto, addr, name, typ string, code int) {
	qt := dns.StringToType[typ]

	ret, err := query(proto, addr, name, typ, nil)
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
