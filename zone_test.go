package newdns

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestZoneValidate(t *testing.T) {
	table := []struct {
		zne Zone
		err string
	}{
		{
			zne: Zone{
				Name: "foo",
			},
			err: "name not fully qualified: foo",
		},
		{
			zne: Zone{
				Name:             "example.com.",
				MasterNameServer: "foo",
			},
			err: "master server not full qualified: foo",
		},
		{
			zne: Zone{
				Name:             "example.com.",
				MasterNameServer: "n1.example.com.",
			},
			err: "missing name servers",
		},
		{
			zne: Zone{
				Name:             "example.com.",
				MasterNameServer: "n1.example.com.",
				AllNameServers: []string{
					"foo",
				},
			},
			err: "name server not fully qualified: foo",
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
			err: "admin email cannot be converted to a domain name: foo@bar..example.com",
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
			err: "retry must be less than refresh: 2",
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
			err: "expire must be bigger than the sum of refresh and retry: 1",
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

func TestZoneLookup(t *testing.T) {
	zone := Zone{
		Name:             "example.com.",
		MasterNameServer: "ns1.example.com.",
		AllNameServers: []string{
			"ns1.example.com.",
			"ns2.example.com.",
		},
		Handler: func(name string) ([]Set, error) {
			if name == "error" {
				return nil, io.EOF
			}

			if name == "invalid1" {
				return []Set{
					{Name: "foo"},
				}, nil
			}

			if name == "invalid2" {
				return []Set{
					{Name: "foo.", Type: A, Records: []Record{{Address: "1.2.3.4"}}},
				}, nil
			}

			if name == "multiple" {
				return []Set{
					{Name: "foo.example.com.", Type: A, Records: []Record{{Address: "1.2.3.4"}}},
					{Name: "foo.example.com.", Type: A, Records: []Record{{Address: "1.2.3.4"}}},
				}, nil
			}

			if name == "" {
				return []Set{
					{Name: "example.com.", Type: CNAME, Records: []Record{{Address: "cool.com."}}},
				}, nil
			}

			if name == "cname" {
				return []Set{
					{Name: "cname.example.com.", Type: A, Records: []Record{{Address: "1.2.3.4"}}},
					{Name: "cname.example.com.", Type: CNAME, Records: []Record{{Address: "cool.com."}}},
				}, nil
			}

			return nil, nil
		},
	}

	err := zone.Validate()
	assert.NoError(t, err)

	res, exists, err := zone.Lookup("foo", A)
	assert.Equal(t, "name does not belong to zone: foo", err.Error())
	assert.False(t, exists)
	assert.Nil(t, res)

	res, exists, err = zone.Lookup("error.example.com.", A)
	assert.Equal(t, "handler error: EOF", err.Error())
	assert.False(t, exists)
	assert.Nil(t, res)

	res, exists, err = zone.Lookup("invalid1.example.com.", A)
	assert.Equal(t, "invalid set: invalid name: foo", err.Error())
	assert.False(t, exists)
	assert.Nil(t, res)

	res, exists, err = zone.Lookup("invalid2.example.com.", A)
	assert.Equal(t, "set does not belong to zone: foo.", err.Error())
	assert.False(t, exists)
	assert.Nil(t, res)

	res, exists, err = zone.Lookup("multiple.example.com.", A)
	assert.Equal(t, "multiple sets for same type", err.Error())
	assert.False(t, exists)
	assert.Nil(t, res)

	res, exists, err = zone.Lookup("example.com.", A)
	assert.Equal(t, "invalid CNAME set at apex: example.com.", err.Error())
	assert.False(t, exists)
	assert.Nil(t, res)

	res, exists, err = zone.Lookup("cname.example.com.", A)
	assert.Equal(t, "other sets with CNAME set: cname.example.com.", err.Error())
	assert.False(t, exists)
	assert.Nil(t, res)
}
