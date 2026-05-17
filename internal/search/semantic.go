package search

import (
	"hash/fnv"
	"math"
	"sort"
	"strings"
)

const semanticDimensions = 192

type SemanticDocument struct {
	Kind     string    `json:"kind"`
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Excerpt  string    `json:"excerpt"`
	Features []string  `json:"features"`
	Vector   []float64 `json:"vector"`
}

func BuildSemanticIndex(records []Record) []SemanticDocument {
	docs := make([]SemanticDocument, 0, len(records))
	for _, rec := range records {
		payload := rec.Payload
		if rec.Kind == "credential" {
			payload = withoutSecret(payload)
		}
		material := searchableMaterial(rec.Kind, payload)
		features := semanticFeatures(material)
		docs = append(docs, SemanticDocument{
			Kind:     rec.Kind,
			ID:       rec.ID,
			Title:    title(payload),
			Excerpt:  excerpt(strings.ToLower(material), nil),
			Features: featureKeys(features),
			Vector:   embedFeatures(features),
		})
	}
	return docs
}

func SemanticRanked(records []Record, query string, limit int) []Hit {
	return SearchSemanticIndex(BuildSemanticIndex(records), query, "", limit)
}

func SearchSemanticIndex(index []SemanticDocument, query, kind string, limit int) []Hit {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	queryFeatures := semanticFeatures(query)
	queryVector := embedFeatures(queryFeatures)
	hits := make([]Hit, 0, len(index))
	for _, doc := range index {
		if kind != "" && kind != "all" && doc.Kind != kind {
			continue
		}
		overlap := semanticOverlapScore(doc.Features, queryFeatures)
		if overlap == 0 {
			continue
		}
		score := cosine(queryVector, doc.Vector)
		if score < 0 {
			score = 0
		}
		rankedScore := int(math.Round(score*1000 + math.Min(overlap*45, 300)))
		if rankedScore == 0 {
			continue
		}
		hits = append(hits, Hit{
			Kind:    doc.Kind,
			ID:      doc.ID,
			Title:   doc.Title,
			Excerpt: doc.Excerpt,
			Score:   rankedScore,
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

func embed(text string) []float64 {
	return embedFeatures(semanticFeatures(text))
}

func embedFeatures(features map[string]float64) []float64 {
	vector := make([]float64, semanticDimensions)
	for feature, weight := range features {
		if feature == "" || weight == 0 {
			continue
		}
		bucket, sign := semanticBucket(feature)
		vector[bucket] += sign * weight
	}
	normalize(vector)
	return vector
}

func featureKeys(features map[string]float64) []string {
	keys := make([]string, 0, len(features))
	for feature := range features {
		keys = append(keys, feature)
	}
	sort.Strings(keys)
	return keys
}

func semanticOverlapScore(docFeatures []string, queryFeatures map[string]float64) float64 {
	var score float64
	for _, feature := range docFeatures {
		if queryFeatures[feature] > 0 {
			score += queryFeatures[feature]
		}
	}
	return score
}

func semanticFeatures(text string) map[string]float64 {
	terms := tokens(text)
	features := make(map[string]float64, len(terms)*3)
	for i, term := range terms {
		features[term] += 1
		for _, expanded := range semanticAliases[term] {
			features[expanded] += 0.65
		}
		if i > 0 {
			features[terms[i-1]+" "+term] += 1.25
		}
		if i > 1 {
			features[terms[i-2]+" "+terms[i-1]+" "+term] += 1.5
		}
	}
	return features
}

func semanticBucket(feature string) (int, float64) {
	h := fnv.New64a()
	_, _ = h.Write([]byte(feature))
	sum := h.Sum64()
	sign := 1.0
	if sum&1 == 1 {
		sign = -1
	}
	return int((sum >> 1) % semanticDimensions), sign
}

func normalize(vector []float64) {
	var sum float64
	for _, value := range vector {
		sum += value * value
	}
	if sum == 0 {
		return
	}
	scale := math.Sqrt(sum)
	for i := range vector {
		vector[i] /= scale
	}
}

func cosine(left, right []float64) float64 {
	if len(left) != len(right) {
		return 0
	}
	var score float64
	for i := range left {
		score += left[i] * right[i]
	}
	return score
}

var semanticAliases = map[string][]string{
	"admin":           {"administrator", "privilege", "authorization", "access"},
	"administrator":   {"admin", "privilege", "authorization", "access"},
	"auth":            {"authentication", "login", "session", "access"},
	"authenticated":   {"authentication", "login", "session", "access"},
	"authentication":  {"auth", "login", "session", "access"},
	"authorization":   {"permission", "privilege", "access", "admin"},
	"certificate":     {"tls", "ssl", "crypto"},
	"cipher":          {"tls", "ssl", "crypto"},
	"command":         {"rce", "execution", "shell"},
	"bypass":          {"unauthenticated", "unauthorized", "access"},
	"credential":      {"password", "secret", "token"},
	"credentials":     {"password", "secret", "token"},
	"database":        {"sql", "sqli", "injection"},
	"disclosure":      {"exposure", "leak", "information"},
	"execution":       {"rce", "command", "shell"},
	"exposure":        {"disclosure", "leak", "information"},
	"injection":       {"sqli", "sql", "database"},
	"login":           {"auth", "authentication", "session"},
	"password":        {"credential", "secret", "token", "login"},
	"permission":      {"authorization", "privilege", "access"},
	"privilege":       {"admin", "permission", "authorization", "access"},
	"proof":           {"evidence", "screenshot", "validation"},
	"rce":             {"command", "execution", "shell"},
	"read":            {"access", "disclosure", "exposure"},
	"screenshot":      {"proof", "evidence", "validation"},
	"secret":          {"credential", "password", "token"},
	"session":         {"auth", "authentication", "login"},
	"shell":           {"rce", "command", "execution"},
	"sql":             {"sqli", "injection", "database"},
	"sqli":            {"sql", "injection", "database"},
	"ssl":             {"tls", "certificate", "cipher", "crypto"},
	"token":           {"credential", "password", "secret"},
	"tls":             {"ssl", "certificate", "cipher", "crypto"},
	"unauthenticated": {"anonymous", "auth", "authentication", "access"},
	"unauthorized":    {"authorization", "permission", "access"},
	"validation":      {"proof", "evidence", "screenshot"},
	"vulnerability":   {"finding", "issue", "risk"},
	"vulnerabilities": {"finding", "issue", "risk"},
	"xss":             {"script", "cross-site", "injection"},
	"cross-site":      {"xss", "script", "injection"},
}
