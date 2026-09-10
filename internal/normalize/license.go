package normalize

import "strings"

// LicenseTokens naively tokenizes an SPDX license expression into its license
// identifiers: parentheses become whitespace, the tokens are split on
// whitespace, and the operators OR, AND, WITH are dropped. Duplicates are
// removed, preserving first-seen order. Operator semantics are deliberately
// ignored; see DESIGN.md.
func LicenseTokens(expression string) []string {
	cleaned := strings.NewReplacer("(", " ", ")", " ").Replace(expression)
	var tokens []string
	seen := make(map[string]bool)
	for _, tok := range strings.Fields(cleaned) {
		if isOperator(tok) || seen[tok] {
			continue
		}
		seen[tok] = true
		tokens = append(tokens, tok)
	}
	return tokens
}

func isOperator(tok string) bool {
	switch strings.ToUpper(tok) {
	case "OR", "AND", "WITH":
		return true
	}
	return false
}

// LicenseKey derives the single non-null dedupe key for a license:
// "spdx:<lowercased id>" when an SPDX id is present, else "name:<lowercased name>".
func LicenseKey(spdxID, name string) string {
	if id := strings.TrimSpace(spdxID); id != "" {
		return "spdx:" + strings.ToLower(id)
	}
	return "name:" + strings.ToLower(strings.TrimSpace(name))
}
