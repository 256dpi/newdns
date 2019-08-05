package newdns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSet(t *testing.T) {
	table := []struct {
		set Set
		err string
	}{
		{
			set: Set{},
			err: "invalid name",
		},
		{
			set: Set{
				Name: "hello.com.",
			},
			err: "name does not belong to zone",
		},
		{
			set: Set{
				Name: "example.com.",
			},
			err: "invalid type",
		},
		{
			set: Set{
				Name: "example.com.",
				Type: TypeA,
			},
			err: "missing records",
		},
		{
			set: Set{
				Name:    "example.com.",
				Type:    TypeA,
				Records: []Record{{}},
			},
			err: "invalid IPv4 address",
		},
		{
			set: Set{
				Name:    "example.com.",
				Type:    TypeTXT,
				Records: []Record{{}},
			},
			err: "missing data",
		},
		{
			set: Set{
				Name:    "example.com.",
				Type:    TypeCNAME,
				Records: []Record{{}, {}},
			},
			err: "multiple CNAME records",
		},
	}

	for i, item := range table {
		err := item.set.Validate("example.com.")
		if err != nil {
			assert.EqualValues(t, item.err, err.Error(), i)
		} else {
			assert.Equal(t, item.err, "", item)
		}
	}
}
