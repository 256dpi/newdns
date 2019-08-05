# newdns

[![Build Status](https://travis-ci.org/256dpi/newdns.svg?branch=master)](https://travis-ci.org/256dpi/newdns)
[![Coverage Status](https://coveralls.io/repos/github/256dpi/newdns/badge.svg?branch=master)](https://coveralls.io/github/256dpi/newdns?branch=master)
[![GoDoc](https://godoc.org/github.com/256dpi/newdns?status.svg)](http://godoc.org/github.com/256dpi/newdns)
[![Release](https://img.shields.io/github/release/256dpi/newdns.svg)](https://github.com/256dpi/newdns/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/256dpi/newdns)](https://goreportcard.com/report/github.com/256dpi/newdns)
 
**A library for building custom DNS servers in Go.**

## Example

```go
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
```
