package newdns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTransferCase(t *testing.T) {
	table := []struct {
		src string
		dst string
		out string
	}{
		{
			src: "example.com",
			dst: "example.com",
			out: "example.com",
		},
		{
			src: "EXAmple.com",
			dst: "example.com",
			out: "EXAmple.com",
		},
		{
			src: "FOO.com",
			dst: "bar.com",
			out: "bar.com",
		},
		{
			src: "foo.EXAmple.com",
			dst: "example.com",
			out: "EXAmple.com",
		},
		{
			src: "foo.EXAmple.com",
			dst: "bar.example.com",
			out: "bar.example.com",
		},
	}

	for i, item := range table {
		assert.Equal(t, item.out, transferCase(item.src, item.dst), i)
	}
}
