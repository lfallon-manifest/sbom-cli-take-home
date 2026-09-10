package normalize

import "testing"

func TestPackageKey(t *testing.T) {
	tests := []struct {
		name    string
		purl    string
		group   string
		pkgName string
		version string
		want    string
	}{
		{
			name: "strips qualifiers",
			purl: "pkg:npm/Foo@1.2.3?arch=x64",
			want: "pkg:npm/Foo@1.2.3",
		},
		{
			name: "lowercases type",
			purl: "pkg:NPM/lodash@4.17.21",
			want: "pkg:npm/lodash@4.17.21",
		},
		{
			name: "lowercases namespace and strips subpath, keeps name case",
			purl: "pkg:maven/Org.Apache/Log4j@2.17.1#sub/path",
			want: "pkg:maven/org.apache/Log4j@2.17.1",
		},
		{
			name: "multi-segment namespace unchanged",
			purl: "pkg:golang/golang.org/x/crypto@v0.21.0",
			want: "pkg:golang/golang.org/x/crypto@v0.21.0",
		},
		{
			name: "qualifiers and subpath together",
			purl: "pkg:NPM/qs@6.11.0?foo=bar#sub",
			want: "pkg:npm/qs@6.11.0",
		},
		{
			name: "uppercase scheme",
			purl: "PKG:npm/left-pad@1.3.0",
			want: "pkg:npm/left-pad@1.3.0",
		},
		{
			name: "purl wins over group/name/version",
			purl: "pkg:npm/express@4.18.2", group: "g", pkgName: "n", version: "v",
			want: "pkg:npm/express@4.18.2",
		},
		{
			name: "purl with surrounding whitespace",
			purl: "  pkg:npm/express@4.18.2  ",
			want: "pkg:npm/express@4.18.2",
		},
		{
			name: "malformed purl without pkg scheme falls back to trimmed input",
			purl: "  npm/express@4.18.2 ",
			want: "npm/express@4.18.2",
		},
		{
			name: "malformed purl without slash lowercases scheme only",
			purl: "PKG:Weird",
			want: "pkg:Weird",
		},
		{
			name:  "no purl full generic",
			group: "acme", pkgName: "internal-lib", version: "0.1.0",
			want: "generic:acme/internal-lib@0.1.0",
		},
		{
			name:    "no purl no group",
			pkgName: "internal-lib", version: "0.1.0",
			want: "generic:internal-lib@0.1.0",
		},
		{
			name:  "no purl no version",
			group: "acme", pkgName: "internal-lib",
			want: "generic:acme/internal-lib",
		},
		{
			name:    "no purl name only",
			pkgName: "internal-lib",
			want:    "generic:internal-lib",
		},
		{
			name:  "no purl trims whitespace",
			group: " acme ", pkgName: " lib ", version: " 1 ",
			want: "generic:acme/lib@1",
		},
		{
			name: "everything empty",
			want: "generic:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PackageKey(tt.purl, tt.group, tt.pkgName, tt.version)
			if got != tt.want {
				t.Errorf("PackageKey(%q, %q, %q, %q) = %q, want %q",
					tt.purl, tt.group, tt.pkgName, tt.version, got, tt.want)
			}
		})
	}
}

func TestPurlType(t *testing.T) {
	tests := []struct {
		purl string
		want string
	}{
		{"pkg:npm/express@4.18.2", "npm"},
		{"pkg:NPM/qs@6.11.0?foo=bar", "npm"},
		{"pkg:golang/golang.org/x/crypto@v0.21.0", "golang"},
		{"pkg:Maven/org.apache/log4j@2.17.1", "maven"},
		{"", ""},
		{"not-a-purl", ""},
		{"pkg:", ""},
		{"pkg:nosplash", ""},
	}
	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			if got := PurlType(tt.purl); got != tt.want {
				t.Errorf("PurlType(%q) = %q, want %q", tt.purl, got, tt.want)
			}
		})
	}
}
