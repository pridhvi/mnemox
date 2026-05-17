package search

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

var tokenRE = regexp.MustCompile(`[a-z0-9_.:/-]+`)

type Record struct {
	ID      string
	Kind    string
	Payload map[string]any
}

type Hit struct {
	Kind    string
	ID      string
	Title   string
	Excerpt string
	Score   int
}

func Ranked(records []Record, query string, limit int) []Hit {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return nil
	}
	queryTokens := tokens(query)
	var hits []Hit
	for _, rec := range records {
		payload := rec.Payload
		if rec.Kind == "credential" {
			payload = withoutSecret(payload)
		}
		material := searchableMaterial(rec.Kind, payload)
		lower := strings.ToLower(material)
		score := 0
		if strings.Contains(lower, query) {
			score += 40 + len(queryTokens)*4
		}
		fieldWeights := weightedFields(payload)
		for field, weight := range fieldWeights {
			fieldLower := strings.ToLower(field)
			for _, token := range queryTokens {
				if strings.Contains(fieldLower, token) {
					score += weight * 8
				} else if fuzzyMatch(fieldLower, token) {
					score += weight * 3
				}
			}
		}
		for _, token := range queryTokens {
			score += strings.Count(lower, token) * 2
		}
		if score == 0 {
			continue
		}
		hits = append(hits, Hit{
			Kind:    rec.Kind,
			ID:      rec.ID,
			Title:   title(payload),
			Excerpt: excerpt(lower, queryTokens),
			Score:   score,
		})
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Score == hits[j].Score {
			return hits[i].Title < hits[j].Title
		}
		return hits[i].Score > hits[j].Score
	})
	if limit > 0 && len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}

func title(payload map[string]any) string {
	for _, key := range []string{"title", "name", "asset", "value"} {
		if value, ok := payload[key].(string); ok && value != "" {
			return value
		}
	}
	return "untitled"
}

func searchableMaterial(kind string, payload map[string]any) string {
	var parts []string
	parts = append(parts, kind)
	for _, key := range []string{
		"title", "name", "value", "type", "asset", "caption", "summary",
		"technical_details", "impact", "remediation", "validation", "notes", "text",
	} {
		if value, ok := payload[key]; ok {
			parts = append(parts, key+": "+readable(value))
		}
	}
	for _, key := range []string{"affected_scope", "tags", "aliases", "references", "open_questions"} {
		if value, ok := payload[key]; ok {
			parts = append(parts, key+": "+readable(value))
		}
	}
	if len(parts) == 1 {
		data, _ := json.Marshal(payload)
		parts = append(parts, string(data))
	}
	return strings.Join(parts, " | ")
}

func weightedFields(payload map[string]any) map[string]int {
	fields := map[string]int{}
	for _, key := range []string{"title", "name", "value", "asset", "caption"} {
		if value, ok := payload[key].(string); ok {
			fields[value] = 5
		}
	}
	for _, key := range []string{"summary", "technical_details", "impact", "remediation", "notes", "text"} {
		if value, ok := payload[key].(string); ok {
			fields[value] = 3
		}
	}
	for _, key := range []string{"affected_scope", "tags", "aliases", "references"} {
		if values, ok := payload[key].([]any); ok {
			for _, value := range values {
				fields[strings.TrimSpace(toString(value))] = 4
			}
		}
	}
	return fields
}

func tokens(value string) []string {
	raw := tokenRE.FindAllString(strings.ToLower(value), -1)
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, token := range raw {
		if len(token) < 2 || seen[token] {
			continue
		}
		seen[token] = true
		out = append(out, token)
	}
	return out
}

func fuzzyMatch(field, token string) bool {
	for _, fieldToken := range tokens(field) {
		if jaroLike(fieldToken, token) >= 0.86 {
			return true
		}
	}
	return false
}

func jaroLike(a, b string) float64 {
	if a == b {
		return 1
	}
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	distance := levenshtein(a, b)
	return 1 - float64(distance)/math.Max(float64(len(a)), float64(len(b)))
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			cur[j] = min(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

func excerpt(text string, terms []string) string {
	start := 0
	for _, term := range terms {
		if idx := strings.Index(text, term); idx >= 0 {
			start = idx - 70
			if start < 0 {
				start = 0
			}
			break
		}
	}
	end := start + 220
	if end > len(text) {
		end = len(text)
	}
	return strings.ReplaceAll(text[start:end], `\n`, " ")
}

func withoutSecret(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		if key == "secret" {
			continue
		}
		out[key] = value
	}
	return out
}

func toString(value any) string {
	return strings.TrimSpace(fmt.Sprint(value))
}

func readable(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := toString(item); text != "" {
				items = append(items, text)
			}
		}
		return strings.Join(items, ", ")
	default:
		return toString(value)
	}
}
