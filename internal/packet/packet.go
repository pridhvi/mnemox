package packet

import (
	"fmt"
	"sort"
	"strings"

	"mnemox/internal/vault"
)

type CitationBundleOptions struct {
	AssetID string
}

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

func RenderCitationBundle(v *vault.Vault, findingID string, options CitationBundleOptions) (string, error) {
	rec, err := v.GetRecord(findingID)
	if err != nil {
		return "", err
	}
	if rec.Kind != "finding" {
		return "", fmt.Errorf("record is not a finding")
	}
	finding := rec.Payload
	assets, err := v.Linked(findingID, "affects_asset")
	if err != nil {
		return "", err
	}
	notes, err := v.Linked(findingID, "has_note")
	if err != nil {
		return "", err
	}
	evidence, err := v.Linked(findingID, "has_evidence")
	if err != nil {
		return "", err
	}
	if options.AssetID != "" {
		assets = filterRecordsByID(assets, options.AssetID)
		notes = filterRecordsLinkedToAsset(v, notes, "note_asset", options.AssetID)
		evidence = filterRecordsLinkedToAsset(v, evidence, "evidence_asset", options.AssetID)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Evidence Citation Bundle: %s\n\n", value(finding, "title", "Untitled Finding"))
	fmt.Fprintf(&b, "- Citation bundle: `[finding:%s]`\n", shortID(rec.ID))
	fmt.Fprintf(&b, "- Status: %s\n", value(finding, "status", "draft"))
	fmt.Fprintf(&b, "- Severity: %s\n", value(finding, "severity", "Unscored"))
	if scope := renderValue(finding["affected_scope"]); scope != "" {
		fmt.Fprintf(&b, "- Affected scope:\n%s\n", indent(scope))
	}
	b.WriteString("\n")

	if summary := value(finding, "summary", ""); summary != "" {
		fmt.Fprintf(&b, "## Finding Summary\n\n%s\n\n", summary)
	}
	if details := value(finding, "technical_details", ""); details != "" {
		fmt.Fprintf(&b, "## Technical Context\n\n%s\n\n", details)
	}

	if len(assets) > 0 {
		b.WriteString("## Cited Assets\n\n")
		for _, asset := range assets {
			fmt.Fprintf(&b, "- `[asset:%s]` **%s** (%s) `%s`\n", shortID(asset.ID), recordName(asset), value(asset.Payload, "type", "asset"), value(asset.Payload, "value", ""))
		}
		b.WriteString("\n")
	}

	if len(evidence) > 0 {
		b.WriteString("## Cited Evidence\n\n")
		for _, item := range evidence {
			caption := firstNonEmpty(value(item.Payload, "caption", ""), value(item.Payload, "original_path", "Evidence item"))
			fmt.Fprintf(&b, "- `[evidence:%s]` **%s**: %s", shortID(item.ID), value(item.Payload, "kind", "file"), caption)
			if originalPath := value(item.Payload, "original_path", ""); originalPath != "" {
				fmt.Fprintf(&b, " Source: `%s`.", originalPath)
			}
			if blobID := value(item.Payload, "blob_id", ""); blobID != "" {
				fmt.Fprintf(&b, " Blob: `%s`.", blobID)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(notes) > 0 {
		b.WriteString("## Cited Operator Notes\n\n")
		for _, note := range notes {
			fmt.Fprintf(&b, "- `[note:%s]` %s", shortID(note.ID), value(note.Payload, "text", ""))
			if asset := value(note.Payload, "asset", ""); asset != "" {
				fmt.Fprintf(&b, " Asset: `%s`.", asset)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## Prompt-Ready Context\n\n")
	fmt.Fprintf(&b, "Use the following cited facts when drafting or validating report text for `%s`.\n\n", value(finding, "title", "Untitled Finding"))
	if len(evidence) == 0 && len(notes) == 0 {
		b.WriteString("- No linked evidence or notes are currently available for this scope.\n")
	} else {
		for _, item := range evidence {
			fmt.Fprintf(&b, "- Evidence `[evidence:%s]` supports the finding: %s.\n", shortID(item.ID), firstNonEmpty(value(item.Payload, "caption", ""), value(item.Payload, "original_path", "Evidence item")))
		}
		for _, note := range notes {
			fmt.Fprintf(&b, "- Note `[note:%s]`: %s\n", shortID(note.ID), value(note.Payload, "text", ""))
		}
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

func filterRecordsByID(records []vault.Record, id string) []vault.Record {
	var out []vault.Record
	for _, rec := range records {
		if rec.ID == id {
			out = append(out, rec)
		}
	}
	return out
}

func filterRecordsLinkedToAsset(v *vault.Vault, records []vault.Record, relation, assetID string) []vault.Record {
	var out []vault.Record
	for _, rec := range records {
		assets, err := v.Linked(rec.ID, relation)
		if err != nil {
			continue
		}
		for _, asset := range assets {
			if asset.ID == assetID {
				out = append(out, rec)
				break
			}
		}
	}
	return out
}

func recordName(rec vault.Record) string {
	return firstNonEmpty(value(rec.Payload, "title", ""), value(rec.Payload, "name", ""), value(rec.Payload, "caption", ""), value(rec.Payload, "text", ""), rec.ID)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func indent(value string) string {
	lines := strings.Split(value, "\n")
	for i := range lines {
		lines[i] = "  " + lines[i]
	}
	return strings.Join(lines, "\n")
}

func shortID(id string) string {
	if len(id) < 8 {
		return id
	}
	return id[:8]
}
