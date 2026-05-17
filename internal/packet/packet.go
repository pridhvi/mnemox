package packet

import (
	"fmt"
	"sort"
	"strings"

	"mnemox/internal/vault"
)

func Render(v *vault.Vault, findingID string) (string, error) {
	rec, err := v.GetRecord(findingID)
	if err != nil {
		return "", err
	}
	finding := rec.Payload
	notes, err := v.Linked(findingID, "has_note")
	if err != nil {
		return "", err
	}
	evidence, err := v.Linked(findingID, "has_evidence")
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", value(finding, "title", "Untitled Finding"))
	fmt.Fprintf(&b, "**Status:** %s\n", value(finding, "status", "draft"))
	fmt.Fprintf(&b, "**Severity:** %s\n", value(finding, "severity", "Unscored"))
	if cvssMap, ok := finding["cvss"].(map[string]any); ok {
		fmt.Fprintf(&b, "**CVSS v4.0 Base Score:** %v (%s)\n", cvssMap["score"], value(cvssMap, "severity", "Unknown"))
		fmt.Fprintf(&b, "**CVSS v4.0 Vector:** `%s`\n", value(cvssMap, "vector", ""))
		if notes := value(cvssMap, "notes", ""); notes != "" {
			fmt.Fprintf(&b, "**CVSS Scoring Notes:** %s\n", notes)
		}
	}
	b.WriteString("\n")

	for _, section := range []struct {
		Title string
		Key   string
	}{
		{"Affected Scope", "affected_scope"},
		{"Summary", "summary"},
		{"Technical Details", "technical_details"},
		{"Impact", "impact"},
		{"Remediation", "remediation"},
		{"Validation", "validation"},
		{"References", "references"},
		{"Open Questions", "open_questions"},
	} {
		if rendered := renderValue(finding[section.Key]); rendered != "" {
			fmt.Fprintf(&b, "## %s\n\n%s\n\n", section.Title, rendered)
		}
	}

	if len(notes) > 0 {
		b.WriteString("## Operator Notes\n\n")
		for _, note := range notes {
			asset := ""
			if value(note.Payload, "asset", "") != "" {
				asset = fmt.Sprintf(" Asset: `%s`.", value(note.Payload, "asset", ""))
			}
			fmt.Fprintf(&b, "- %s%s [note:%s]\n", value(note.Payload, "text", ""), asset, shortID(note.ID))
		}
		b.WriteString("\n")
	}

	if len(evidence) > 0 {
		b.WriteString("## Evidence\n\n")
		for _, item := range evidence {
			caption := value(item.Payload, "caption", "")
			if caption == "" {
				caption = value(item.Payload, "original_path", "Evidence item")
			}
			blob := ""
			if value(item.Payload, "blob_id", "") != "" {
				blob = fmt.Sprintf(" Blob: `%s`.", value(item.Payload, "blob_id", ""))
			}
			fmt.Fprintf(&b, "- **%s:** %s.%s [evidence:%s]\n", value(item.Payload, "kind", "file"), caption, blob, shortID(item.ID))
		}
		b.WriteString("\n")
	}

	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

func value(payload map[string]any, key, fallback string) string {
	if v, ok := payload[key].(string); ok {
		return v
	}
	return fallback
}

func renderValue(v any) string {
	switch typed := v.(type) {
	case string:
		return typed
	case []any:
		if len(typed) == 0 {
			return ""
		}
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			if s := fmt.Sprint(item); s != "" {
				items = append(items, "- "+s)
			}
		}
		sort.Strings(items)
		return strings.Join(items, "\n")
	default:
		return ""
	}
}

func shortID(id string) string {
	if len(id) < 8 {
		return id
	}
	return id[:8]
}
