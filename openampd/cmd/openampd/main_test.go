package main

import (
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/ConcatenaLabs/openamp/openampd/internal/server"
)

// A unit that still passes -arcaenclave must start: the flag parses, its
// value reaches nothing, and it is named once in the log.
func TestArcaEnclaveAcceptedAndIgnored(t *testing.T) {
	t.Setenv("OPENAMPD_ARCA_ENCLAVE", "")
	fs := flag.NewFlagSet("openampd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	v := retiredArcaEnclave(fs)
	if err := fs.Parse([]string{"-arcaenclave", "/root/.local/bin/arca-enclave", "-other"}); err == nil {
		t.Fatal("an unknown flag beside it must still be refused")
	}
	fs = flag.NewFlagSet("openampd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	v = retiredArcaEnclave(fs)
	if err := fs.Parse([]string{"-arcaenclave", "/root/.local/bin/arca-enclave"}); err != nil {
		t.Fatalf("-arcaenclave refused: %v", err)
	}
	note := arcaEnclaveNote(*v)
	if !strings.Contains(note, server.EnclaveRetired) || !strings.Contains(note, "ignored") {
		t.Fatalf("log line = %q", note)
	}
	if arcaEnclaveNote("") != "" {
		t.Fatal("an unset -arcaenclave must log nothing")
	}
}

// The environment variable is accepted the same way.
func TestArcaEnclaveEnvAccepted(t *testing.T) {
	t.Setenv("OPENAMPD_ARCA_ENCLAVE", "/opt/arca-enclave")
	fs := flag.NewFlagSet("openampd", flag.ContinueOnError)
	v := retiredArcaEnclave(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(arcaEnclaveNote(*v), "/opt/arca-enclave") {
		t.Fatalf("log line = %q", arcaEnclaveNote(*v))
	}
}
