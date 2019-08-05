package newdns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsDomain(t *testing.T) {
	assert.True(t, IsDomain("example.com", false))
	assert.False(t, IsDomain("example.com", true))
	assert.True(t, IsDomain("example.com.", true))
	assert.False(t, IsDomain("", false))
	assert.True(t, IsDomain("x", false))
}

func TestInZone(t *testing.T) {
	assert.True(t, InZone("example.com.", "foo.example.com."))
	assert.True(t, InZone("example.com", "foo.example.com"))
	assert.True(t, InZone("example.com", "example.com"))
	assert.False(t, InZone("foo.example.com", "example.com"))
}

func TestTrimZone(t *testing.T) {
	assert.Equal(t, "foo", TrimZone("example.com.", "foo.example.com."))
	assert.Equal(t, "foo", TrimZone("example.com", "foo.example.com"))
	assert.Equal(t, "", TrimZone("example.com", "example.com"))
	assert.Equal(t, "example.com", TrimZone("foo.example.com", "example.com"))
}

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
