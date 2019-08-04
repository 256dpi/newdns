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
			err: "invalid type",
		},
		{
			set: Set{Type: TypeA},
			err: "missing records",
		},
		{
			set: Set{Type: TypeA, Records: []Record{{}}},
			err: "invalid IPv4 address",
		},
		{
			set: Set{Type: TypeTXT, Records: []Record{{}}},
			err: "missing data",
		},
		{
			set: Set{Type: TypeCNAME, Records: []Record{{},{}}},
			err: "multiple CNAME records",
		},
	}

	for i, item := range table {
		err := item.set.Validate()
		if err != nil {
			assert.EqualValues(t, item.err, err.Error(), i)
		} else {
			assert.Equal(t, item.err, "", item)
		}
	}
}
