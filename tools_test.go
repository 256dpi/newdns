package newdns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsDomain(t *testing.T) {
	assert.True(t, IsDomain("example.com", false))
	assert.False(t, IsDomain("example.com", true))
	assert.True(t, IsDomain("example.com.", true))
	assert.True(t, IsDomain(" example.com.", true))
	assert.True(t, IsDomain("example.com. ", true))
	assert.False(t, IsDomain("", false))
	assert.True(t, IsDomain("x", false))
	assert.True(t, IsDomain(".", false))
}

func TestInZone(t *testing.T) {
	assert.True(t, InZone("example.com.", "foo.example.com."))
	assert.True(t, InZone("example.com", "foo.example.com"))
	assert.True(t, InZone("example.com", "example.com"))
	assert.True(t, InZone(".", "com"))
	assert.True(t, InZone(".", "."))
	assert.False(t, InZone("", "."))
	assert.False(t, InZone("", ""))
	assert.False(t, InZone("foo.example.com", "example.com"))
}

func TestTrimZone(t *testing.T) {
	assert.Equal(t, "foo", TrimZone("example.com.", "foo.example.com."))
	assert.Equal(t, "foo", TrimZone("example.com", "foo.example.com"))
	assert.Equal(t, "", TrimZone("example.com", "example.com"))
	assert.Equal(t, "example.com", TrimZone("foo.example.com", "example.com"))
}

func TestNormalizeDomain(t *testing.T) {
	assert.Equal(t, "", NormalizeDomain("", false, false))
	assert.Equal(t, ".", NormalizeDomain("", false, true))
	assert.Equal(t, "foo", NormalizeDomain(" foo", false, false))
	assert.Equal(t, "foo", NormalizeDomain("foo ", false, false))
	assert.Equal(t, "foo", NormalizeDomain(" fOO ", true, false))
	assert.Equal(t, "foo.", NormalizeDomain(" fOO ", true, true))
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
		assert.Equal(t, item.out, TransferCase(item.src, item.dst), i)
	}
}
