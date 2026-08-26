package httputil

import "testing"

func TestLookupValue(t *testing.T) {
	tests := []struct { name, input string; wantOK bool }{
		{name: "ipv4", input: "192.0.2.1", wantOK: true},
		{name: "ipv6", input: "2001:db8::1", wantOK: true},
		{name: "cidr", input: "192.0.2.0/24", wantOK: true},
		{name: "hostname", input: "Example.COM.", wantOK: true},
		{name: "empty", input: "", wantOK: false},
		{name: "path", input: "example.com/path", wantOK: false},
		{name: "newline", input: "example.com\\nheader", wantOK: false},
	}
	for _, tt := range tests {
		got, err := LookupValue(tt.input)
		if (err == nil) != tt.wantOK { t.Errorf("%s: error = %v, wantOK = %v", tt.name, err, tt.wantOK) }
		if tt.wantOK && got == "" { t.Errorf("%s: empty normalized result", tt.name) }
	}
}
