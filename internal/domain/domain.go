package domain

type Finding struct {
	Title            string   `json:"title"`
	Status           string   `json:"status"`
	Severity         string   `json:"severity"`
	AffectedScope    []string `json:"affected_scope"`
	Summary          string   `json:"summary"`
	TechnicalDetails string   `json:"technical_details"`
	Impact           string   `json:"impact"`
	Remediation      string   `json:"remediation"`
	Validation       string   `json:"validation"`
	References       []string `json:"references"`
	OpenQuestions    []string `json:"open_questions"`
	CVSS             any      `json:"cvss,omitempty"`
}

type Asset struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Value string   `json:"value"`
	Tags  []string `json:"tags"`
	Notes string   `json:"notes"`
}

type Evidence struct {
	Kind         string   `json:"kind"`
	Caption      string   `json:"caption"`
	OriginalPath string   `json:"original_path"`
	BlobID       string   `json:"blob_id"`
	Tags         []string `json:"tags"`
}

type Note struct {
	Text  string   `json:"text"`
	Asset string   `json:"asset"`
	Tags  []string `json:"tags"`
}

type Credential struct {
	Name     string   `json:"name"`
	Username string   `json:"username"`
	Secret   string   `json:"secret,omitempty"`
	Scope    string   `json:"scope"`
	Tags     []string `json:"tags"`
}

func FindingPayload(f Finding) map[string]any {
	payload := map[string]any{
		"title":             f.Title,
		"status":            Default(f.Status, "draft"),
		"severity":          Default(f.Severity, "Unscored"),
		"affected_scope":    StringSlice(f.AffectedScope),
		"summary":           f.Summary,
		"technical_details": f.TechnicalDetails,
		"impact":            f.Impact,
		"remediation":       f.Remediation,
		"validation":        f.Validation,
		"references":        StringSlice(f.References),
		"open_questions":    StringSlice(f.OpenQuestions),
	}
	if f.CVSS != nil {
		payload["cvss"] = f.CVSS
	}
	return payload
}

func AssetPayload(a Asset) map[string]any {
	return map[string]any{
		"name":  a.Name,
		"type":  Default(a.Type, "host"),
		"value": a.Value,
		"tags":  StringSlice(a.Tags),
		"notes": a.Notes,
	}
}

func EvidencePayload(e Evidence) map[string]any {
	return map[string]any{
		"kind":          Default(e.Kind, "file"),
		"caption":       e.Caption,
		"original_path": e.OriginalPath,
		"blob_id":       e.BlobID,
		"tags":          StringSlice(e.Tags),
	}
}

func NotePayload(n Note) map[string]any {
	return map[string]any{"text": n.Text, "asset": n.Asset, "tags": StringSlice(n.Tags)}
}

func CredentialPayload(c Credential) map[string]any {
	return map[string]any{
		"name":     c.Name,
		"username": c.Username,
		"secret":   c.Secret,
		"scope":    c.Scope,
		"tags":     StringSlice(c.Tags),
	}
}

func Default(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func StringSlice(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
