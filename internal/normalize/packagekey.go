// Package normalize holds the pure functions that derive canonical identity
// keys (package_key, license_key) at ingest time.
package normalize

import "strings"

const purlScheme = "pkg:"

// PackageKey derives the canonical package-version identity for a component.
//
// With a purl, the result is the purl with qualifiers and subpath stripped and
// the scheme, type, and namespace lowercased. The name and version keep their
// case because name case sensitivity is ecosystem-dependent.
//
// Without a purl, the result is "generic:{group}/{name}@{version}" with empty
// segments collapsed.
func PackageKey(purl, group, name, version string) string {
	purl = strings.TrimSpace(purl)
	if purl != "" {
		return normalizePurl(purl)
	}
	return genericKey(strings.TrimSpace(group), strings.TrimSpace(name), strings.TrimSpace(version))
}

// PurlType returns the lowercased purl type ("npm", "maven", ...) or "" if the
// string is not a purl with a type segment.
func PurlType(purl string) string {
	typ, _, ok := splitPurl(strings.TrimSpace(purl))
	if !ok {
		return ""
	}
	return typ
}

func normalizePurl(purl string) string {
	typ, rest, ok := splitPurl(purl)
	if !ok {
		return lowercaseScheme(purl)
	}
	segments := strings.Split(rest, "/")
	nameVersion := segments[len(segments)-1]
	namespace := strings.ToLower(strings.Join(segments[:len(segments)-1], "/"))

	var b strings.Builder
	b.WriteString(purlScheme)
	b.WriteString(typ)
	b.WriteByte('/')
	if namespace != "" {
		b.WriteString(namespace)
		b.WriteByte('/')
	}
	b.WriteString(nameVersion)
	return b.String()
}

// splitPurl strips qualifiers and subpath, then returns the lowercased type and
// the remainder after it. ok is false if the input is not "pkg:type/...".
func splitPurl(purl string) (typ, rest string, ok bool) {
	if len(purl) < len(purlScheme) || !strings.EqualFold(purl[:len(purlScheme)], purlScheme) {
		return "", "", false
	}
	body := purl[len(purlScheme):]
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	if i := strings.IndexByte(body, '?'); i >= 0 {
		body = body[:i]
	}
	body = strings.TrimLeft(body, "/")
	typ, rest, found := strings.Cut(body, "/")
	if !found || typ == "" || rest == "" {
		return "", "", false
	}
	return strings.ToLower(typ), rest, true
}

func lowercaseScheme(purl string) string {
	if len(purl) >= len(purlScheme) && strings.EqualFold(purl[:len(purlScheme)], purlScheme) {
		return purlScheme + purl[len(purlScheme):]
	}
	return purl
}

func genericKey(group, name, version string) string {
	var b strings.Builder
	b.WriteString("generic:")
	if group != "" {
		b.WriteString(group)
		b.WriteByte('/')
	}
	b.WriteString(name)
	if version != "" {
		b.WriteByte('@')
		b.WriteString(version)
	}
	return b.String()
}
