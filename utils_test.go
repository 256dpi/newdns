package newdns

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func run(s *Server, addr string, fn func()) {
	defer s.Close()

	go func() {
		err := s.Run(addr)
		if err != nil {
			panic(err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	fn()
}

func equalJSON(t *testing.T, a, b interface{}) {
	buf := new(bytes.Buffer)

	e := json.NewEncoder(buf)
	e.SetIndent("", "  ")

	_ = e.Encode(a)
	aa := buf.String()

	buf.Reset()
	_ = e.Encode(b)
	bb := buf.String()

	assert.JSONEq(t, aa, bb)
}

func isIOError(err error) bool {
	if err == nil {
		return false
	}

	if strings.Contains(err.Error(), "i/o timeout") {
		return true
	}

	if strings.Contains(err.Error(), "connection reset by peer") {
		return true
	}

	return false
}
