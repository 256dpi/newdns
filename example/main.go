package main

import (
	"fmt"

	"github.com/256dpi/newdns"
)

func main() {
	// create zone
	zone := &newdns.Zone{
		Name:             "foo.example.com.",
		MasterNameServer: "ns1.example.com.",
		AllNameServers: []string{
			"ns2.example.com.",
			"ns3.example.com.",
		},
		Handler: func(name string) ([]newdns.Set, error) {
			fmt.Printf("lookup name: \"%s\"\n", name)

			// return apex records
			if name == "" {
				return []newdns.Set{
					{
						Type: newdns.A,
						Records: []newdns.Record{
							{Address: "1.2.3.4"},
						},
					},
					{
						Type: newdns.AAAA,
						Records: []newdns.Record{
							{Address: "1:2:3:4::"},
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
			fmt.Printf("lookup zone: %s\n", name)

			// check name
			if newdns.InZone("foo.example.com.", name) {
				return zone, nil
			}

			return nil, nil
		},
		Reporter: func(err error) {
			println(err.Error())
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
	fmt.Println("USE dig foo.example.com @0.0.0.0 -p 1337")

	// wait forever
	select {}
}
