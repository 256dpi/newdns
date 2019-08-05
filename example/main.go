package main

import (
	"fmt"

	"github.com/miekg/dns"

	"github.com/256dpi/newdns"
)

func main() {
	// create zone
	zone := &newdns.Zone{
		Name:             "example.com.",
		MasterNameServer: "ns1.hostmaster.com.",
		AllNameServers: []string{
			"ns1.hostmaster.com.",
			"ns2.hostmaster.com.",
			"ns3.hostmaster.com.",
		},
		Handler: func(name string) ([]newdns.Set, error) {
			// return apex records
			if name == "" {
				return []newdns.Set{
					{
						Name: "example.com.",
						Type: newdns.A,
						Records: []newdns.Record{
							{Address: "1.2.3.4"},
						},
					},
					{
						Name: "example.com.",
						Type: newdns.AAAA,
						Records: []newdns.Record{
							{Address: "1:2:3:4::"},
						},
					},
				}, nil
			}

			// return sub records
			if name == "foo" {
				return []newdns.Set{
					{
						Name: "foo.example.com.",
						Type: newdns.CNAME,
						Records: []newdns.Record{
							{Address: "bar.example.com."},
						},
					},
				}, nil
			}

			return nil, nil
		},
	}

	// create server
	server := newdns.NewServer(newdns.Config{
		Handler: func(name string) (*newdns.Zone, error) {
			// check name
			if newdns.InZone("example.com.", name) {
				return zone, nil
			}

			return nil, nil
		},
		Logger: func(e newdns.Event, msg *dns.Msg, err error, reason string) {
			fmt.Println(e, err, reason)
		},
	})

	// run server
	go func() {
		err := server.Run(":1337")
		if err != nil {
			panic(err)
		}
	}()

	// print info
	fmt.Println("Query apex: dig example.com @0.0.0.0 -p 1337")
	fmt.Println("Query other: dig foo.example.com @0.0.0.0 -p 1337")

	// wait forever
	select {}
}
