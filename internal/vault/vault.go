package vault

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type Record struct {
	ID        string
	Kind      string
	CreatedAt string
	UpdatedAt string
	Payload   map[string]any
}

type SearchHit struct {
	Kind    string
	ID      string
	Title   string
	Excerpt string
	Score   int
}

type Vault struct {
	Root    string
	DB      *sql.DB
	box     *cipherBox
	BlobDir string
}

func DefaultPath() string {
	if path := os.Getenv("MNEMOX_VAULT"); path != "" {
		abs, _ := filepath.Abs(path)
		return abs
	}
	abs, _ := filepath.Abs(".mnemox")
	return abs
}

func Create(root, name string) (*Vault, error) {
	passphrase, err := readPassphrase(true)
	if err != nil {
		return nil, err
	}
	return CreateWithPassphrase(root, name, passphrase)
}

func CreateWithPassphrase(root, name, passphrase string) (*Vault, error) {
	if root == "" {
		root = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Join(root, "blobs"), 0o700); err != nil {
		return nil, err
	}
	configPath := filepath.Join(root, "config.json")
	if _, err := os.Stat(configPath); err == nil {
		return nil, fmt.Errorf("vault already exists: %s", root)
	}
	cfg, err := newCryptoConfig()
	if err != nil {
		return nil, err
	}
	config := configFile{Name: name, CreatedAt: utcNow(), Crypto: cfg}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(configPath, append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	box, err := newCipherBox(passphrase, cfg)
	if err != nil {
		return nil, err
	}
	v, err := openWithBox(root, box)
	if err != nil {
		return nil, err
	}
	return v, v.Migrate()
}

func Open(root string) (*Vault, error) {
	passphrase, err := readPassphrase(false)
	if err != nil {
		return nil, err
	}
	return OpenWithPassphrase(root, passphrase)
}

func OpenWithPassphrase(root, passphrase string) (*Vault, error) {
	if root == "" {
		root = DefaultPath()
	}
	data, err := os.ReadFile(filepath.Join(root, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("vault not initialized: %s", root)
	}
	var config configFile
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	box, err := newCipherBox(passphrase, config.Crypto)
	if err != nil {
		return nil, err
	}
	v, err := openWithBox(root, box)
	if err != nil {
		return nil, err
	}
	if err := v.Migrate(); err != nil {
		_ = v.Close()
		return nil, err
	}
	if err := v.Verify(); err != nil {
		_ = v.Close()
		return nil, err
	}
	return v, nil
}

func openWithBox(root string, box *cipherBox) (*Vault, error) {
	db, err := sql.Open("sqlite", filepath.Join(root, "vault.db"))
	if err != nil {
		return nil, err
	}
	return &Vault{Root: root, DB: db, box: box, BlobDir: filepath.Join(root, "blobs")}, nil
}

func (v *Vault) Close() error {
	if v.DB == nil {
		return nil
	}
	return v.DB.Close()
}

func (v *Vault) Migrate() error {
	_, err := v.DB.Exec(`
CREATE TABLE IF NOT EXISTS meta (
	key TEXT PRIMARY KEY,
	value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS links (
	id TEXT PRIMARY KEY,
	src_id TEXT NOT NULL,
	dst_id TEXT NOT NULL,
	relation TEXT NOT NULL,
	created_at TEXT NOT NULL
);
`)
	if err != nil {
		return err
	}
	var count int
	if err := v.DB.QueryRow(`SELECT COUNT(*) FROM meta WHERE key = 'verify'`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		token, err := v.box.encrypt([]byte(verifyPlaintext))
		if err != nil {
			return err
		}
		_, err = v.DB.Exec(`INSERT INTO meta(key, value) VALUES('verify', ?)`, token)
		return err
	}
	return nil
}

func (v *Vault) Verify() error {
	var token []byte
	if err := v.DB.QueryRow(`SELECT value FROM meta WHERE key = 'verify'`).Scan(&token); err != nil {
		return err
	}
	plain, err := v.box.decrypt(token)
	if err != nil {
		return errors.New("invalid Mnemox passphrase")
	}
	if string(plain) != verifyPlaintext {
		return errors.New("invalid Mnemox passphrase")
	}
	return nil
}

func (v *Vault) AddRecord(kind string, payload map[string]any) (string, error) {
	id := uuid.NewString()
	now := utcNow()
	token, err := v.box.encryptJSON(payload)
	if err != nil {
		return "", err
	}
	_, err = v.DB.Exec(`INSERT INTO records(id, kind, created_at, updated_at, payload) VALUES (?, ?, ?, ?, ?)`, id, kind, now, now, token)
	return id, err
}

func (v *Vault) UpdateRecord(id string, payload map[string]any) error {
	token, err := v.box.encryptJSON(payload)
	if err != nil {
		return err
	}
	_, err = v.DB.Exec(`UPDATE records SET updated_at = ?, payload = ? WHERE id = ?`, utcNow(), token, id)
	return err
}

func (v *Vault) Records(kind string) ([]Record, error) {
	query := `SELECT id, kind, created_at, updated_at, payload FROM records`
	args := []any{}
	if kind != "" {
		query += ` WHERE kind = ?`
		args = append(args, kind)
	}
	query += ` ORDER BY created_at`
	rows, err := v.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var rec Record
		var token []byte
		if err := rows.Scan(&rec.ID, &rec.Kind, &rec.CreatedAt, &rec.UpdatedAt, &token); err != nil {
			return nil, err
		}
		var payload map[string]any
		if err := v.box.decryptJSON(token, &payload); err != nil {
			return nil, err
		}
		rec.Payload = payload
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (v *Vault) GetRecord(id string) (Record, error) {
	rows, err := v.DB.Query(`SELECT id, kind, created_at, updated_at, payload FROM records WHERE id = ?`, id)
	if err != nil {
		return Record{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return Record{}, fmt.Errorf("record not found: %s", id)
	}
	var rec Record
	var token []byte
	if err := rows.Scan(&rec.ID, &rec.Kind, &rec.CreatedAt, &rec.UpdatedAt, &token); err != nil {
		return Record{}, err
	}
	var payload map[string]any
	if err := v.box.decryptJSON(token, &payload); err != nil {
		return Record{}, err
	}
	rec.Payload = payload
	return rec, rows.Err()
}

func (v *Vault) FindOne(kind, text string) (Record, error) {
	needle := strings.ToLower(text)
	records, err := v.Records(kind)
	if err != nil {
		return Record{}, err
	}
	var matches []Record
	for _, rec := range records {
		title := strings.ToLower(Title(rec.Payload))
		if strings.ToLower(rec.ID) == needle || title == needle {
			return rec, nil
		}
		if strings.Contains(title, needle) {
			matches = append(matches, rec)
		}
	}
	if len(matches) == 0 {
		return Record{}, fmt.Errorf("%s not found: %s", kind, text)
	}
	if len(matches) > 1 {
		names := make([]string, 0, len(matches))
		for _, match := range matches {
			names = append(names, Title(match.Payload))
		}
		return Record{}, fmt.Errorf("ambiguous %s %q; matches: %s", kind, text, strings.Join(names, ", "))
	}
	return matches[0], nil
}

func (v *Vault) AddLink(srcID, dstID, relation string) error {
	_, err := v.DB.Exec(`INSERT INTO links(id, src_id, dst_id, relation, created_at) VALUES (?, ?, ?, ?, ?)`, uuid.NewString(), srcID, dstID, relation, utcNow())
	return err
}

func (v *Vault) Linked(srcID, relation string) ([]Record, error) {
	rows, err := v.DB.Query(`SELECT dst_id FROM links WHERE src_id = ? AND relation = ? ORDER BY created_at`, srcID, relation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		rec, err := v.GetRecord(id)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (v *Vault) LinkCounts(relation string) (map[string]int, error) {
	rows, err := v.DB.Query(`SELECT src_id, COUNT(*) FROM links WHERE relation = ? GROUP BY src_id`, relation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var id string
		var count int
		if err := rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		counts[id] = count
	}
	return counts, rows.Err()
}

func (v *Vault) StoreBlob(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return v.StoreBlobBytes(data)
}

func (v *Vault) StoreBlobBytes(data []byte) (string, error) {
	token, err := v.box.encrypt(data)
	if err != nil {
		return "", err
	}
	id := uuid.NewString()
	if err := os.MkdirAll(v.BlobDir, 0o700); err != nil {
		return "", err
	}
	return id, os.WriteFile(filepath.Join(v.BlobDir, id+".bin"), token, 0o600)
}

func (v *Vault) ExportBlob(id, output string) error {
	plain, err := v.ReadBlob(id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	return os.WriteFile(output, plain, 0o600)
}

func (v *Vault) ReadBlob(id string) ([]byte, error) {
	token, err := os.ReadFile(filepath.Join(v.BlobDir, id+".bin"))
	if err != nil {
		return nil, err
	}
	return v.box.decrypt(token)
}

func (v *Vault) Search(query string, limit int) ([]SearchHit, error) {
	terms := strings.Fields(strings.ToLower(query))
	records, err := v.Records("")
	if err != nil {
		return nil, err
	}
	var hits []SearchHit
	for _, rec := range records {
		payload := rec.Payload
		if rec.Kind == "credential" {
			payload = clonePayloadWithoutSecret(rec.Payload)
		}
		data, _ := json.Marshal(payload)
		haystack := strings.ToLower(string(data))
		score := 0
		for _, term := range terms {
			score += strings.Count(haystack, term)
		}
		if score == 0 {
			continue
		}
		hits = append(hits, SearchHit{
			Kind:    rec.Kind,
			ID:      rec.ID,
			Title:   Title(rec.Payload),
			Excerpt: excerpt(haystack, terms),
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
	return hits, nil
}

func clonePayloadWithoutSecret(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		if key == "secret" {
			continue
		}
		out[key] = value
	}
	return out
}

func Title(payload map[string]any) string {
	for _, key := range []string{"title", "name", "asset"} {
		if value, ok := payload[key].(string); ok && value != "" {
			return value
		}
	}
	return "untitled"
}

func utcNow() string {
	return time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
}

func excerpt(text string, terms []string) string {
	start := 0
	for _, term := range terms {
		if idx := strings.Index(text, term); idx >= 0 {
			start = idx - 60
			if start < 0 {
				start = 0
			}
			break
		}
	}
	end := start + 180
	if end > len(text) {
		end = len(text)
	}
	return strings.ReplaceAll(text[start:end], `\n`, " ")
}
