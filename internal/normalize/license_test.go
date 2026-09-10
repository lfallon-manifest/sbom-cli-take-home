package normalize

import (
	"reflect"
	"testing"
)

func TestLicenseTokens(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want []string
	}{
		{
			name: "or and with parens",
			expr: "(MIT OR Apache-2.0) AND BSD-3-Clause",
			want: []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
		},
		{
			name: "with exception",
			expr: "GPL-2.0-only WITH Classpath-exception-2.0",
			want: []string{"GPL-2.0-only", "Classpath-exception-2.0"},
		},
		{
			name: "plus suffix preserved",
			expr: "GPL-2.0+",
			want: []string{"GPL-2.0+"},
		},
		{
			name: "single id",
			expr: "MIT",
			want: []string{"MIT"},
		},
		{
			name: "lowercase operators dropped",
			expr: "MIT or Apache-2.0 and ISC",
			want: []string{"MIT", "Apache-2.0", "ISC"},
		},
		{
			name: "duplicates collapsed, first-seen order",
			expr: "MIT OR Apache-2.0 OR MIT",
			want: []string{"MIT", "Apache-2.0"},
		},
		{
			name: "nested parens and odd spacing",
			expr: "((MIT)OR(  Apache-2.0 ))",
			want: []string{"MIT", "Apache-2.0"},
		},
		{
			name: "empty",
			expr: "",
			want: nil,
		},
		{
			name: "only operators and parens",
			expr: "( OR AND )",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LicenseTokens(tt.expr)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LicenseTokens(%q) = %#v, want %#v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestLicenseKey(t *testing.T) {
	tests := []struct {
		name   string
		spdxID string
		lic    string
		want   string
	}{
		{name: "spdx id lowercased", spdxID: "MIT", want: "spdx:mit"},
		{name: "spdx id trimmed", spdxID: "  Apache-2.0 ", want: "spdx:apache-2.0"},
		{name: "spdx wins over name", spdxID: "MIT", lic: "Custom", want: "spdx:mit"},
		{name: "name lowercased", lic: "Custom License", want: "name:custom license"},
		{name: "name trimmed", lic: "  Custom  ", want: "name:custom"},
		{name: "both empty", want: "name:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LicenseKey(tt.spdxID, tt.lic); got != tt.want {
				t.Errorf("LicenseKey(%q, %q) = %q, want %q", tt.spdxID, tt.lic, got, tt.want)
			}
		})
	}
}
