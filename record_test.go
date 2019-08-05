package newdns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecord(t *testing.T) {
	table := []struct {
		typ Type
		rec Record
		err string
	}{
		{
			typ: TypeA,
			rec: Record{Address: ""},
			err: "invalid IPv4 address",
		},
		{
			typ: TypeAAAA,
			rec: Record{Address: ""},
			err: "invalid IPv6 address",
		},
		{
			typ: TypeA,
			rec: Record{Address: "1:2:3:4::"},
			err: "invalid IPv4 address",
		},
		{
			typ: TypeA,
			rec: Record{Address: "1.2.3.4"},
		},
		{
			typ: TypeAAAA,
			rec: Record{Address: "1:2:3:4::"},
		},
		{
			typ: TypeCNAME,
			rec: Record{Address: ""},
			err: "invalid domain address",
		},
		{
			typ: TypeCNAME,
			rec: Record{Address: "foo.com"},
			err: "invalid domain address",
		},
		{
			typ: TypeCNAME,
			rec: Record{Address: "foo.com."},
		},
		{
			typ: TypeMX,
			rec: Record{Address: "foo.com"},
			err: "invalid domain address",
		},
		{
			typ: TypeMX,
			rec: Record{Address: "foo.com."},
		},
		{
			typ: TypeTXT,
			rec: Record{Data: nil},
			err: "missing data",
		},
		{
			typ: TypeTXT,
			rec: Record{Data: []string{"z4e6ycRMp6MP3WvWQMxIAOXglxANbj3oB0xD8BffktO4eo3VCR0s6TyGHKixvarOFJU0fqNkXeFOeI7sTXH5X0iXZukfLgnGTxLXNC7KkVFwtVFsh1P0IUNXtNBlOVWrVbxkS62ezbLpENNkiBwbkCvcTjwF2kyI0curAt9JhhJFb3AAq0q1iHWlJLn1KSrev9PIsY3alndDKjYTPxAojxzGKdK3A7rWLJ8Uzb3Z5OhLwP7jTKqbWVUocJRFLYpL"}},
			err: "data too long",
		},
		{
			typ: TypeTXT,
			rec: Record{Data: []string{"foo"}},
		},
	}

	for i, item := range table {
		err := item.rec.Validate(item.typ)
		if err != nil {
			assert.EqualValues(t, item.err, err.Error(), i)
		} else {
			assert.Equal(t, item.err, "", item)
		}
	}
}
