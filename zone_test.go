package newdns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestZone(t *testing.T) {
	table := []struct {
		zne Zone
		err string
	}{
		{
			zne: Zone{},
			err: "name not fully qualified",
		},
		{
			zne: Zone{
				Name: "example.com.",
			},
			err: "master server not full qualified",
		},
		{
			zne: Zone{
				Name:             "example.com.",
				MasterNameServer: "n1.example.com.",
			},
			err: "missing name server",
		},
		{
			zne: Zone{
				Name:             "example.com.",
				MasterNameServer: "n1.example.com.",
				AllNameServers: []string{
					"",
				},
			},
			err: "name server not fully qualified",
		},
		{
			zne: Zone{
				Name:             "example.com.",
				MasterNameServer: "n1.example.com.",
				AllNameServers: []string{
					"n1.example.com.",
				},
			},
		},
		{
			zne: Zone{
				Name:             "example.com.",
				MasterNameServer: "n1.example.com.",
				AllNameServers: []string{
					"n1.example.com.",
				},
				AdminEmail: "foo@bar..example.com",
			},
			err: "admin email cannot be converted to a domain name",
		},
		{
			zne: Zone{
				Name:             "example.com.",
				MasterNameServer: "n1.example.com.",
				AllNameServers: []string{
					"n1.example.com.",
				},
				Refresh: 1,
				Retry:   2,
			},
			err: "retry must be less than refresh",
		},
		{
			zne: Zone{
				Name:             "example.com.",
				MasterNameServer: "n1.example.com.",
				AllNameServers: []string{
					"n1.example.com.",
				},
				Expire: 1,
				Retry:  2,
			},
			err: "expire must be bigger than the sum of refresh and retry",
		},
	}

	for i, item := range table {
		err := item.zne.Validate()
		if err != nil {
			assert.EqualValues(t, item.err, err.Error(), i)
		} else {
			assert.Equal(t, item.err, "", item)
		}
	}
}
