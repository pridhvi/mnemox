package vault

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mnemox/internal/search"

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

const (
	semanticIndexMetaKey = "semantic_index_v1"
	semanticIndexVersion = 2
)

type semanticIndexCache struct {
	Version     int                       `json:"version"`
	Fingerprint string                    `json:"fingerprint"`
	BuiltAt     string                    `json:"built_at"`
	Items       []search.SemanticDocument `json:"items"`
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
	data, err := os.ReadFile(filepath.Join(root, "config.json")) // #nosec G304 -- root is the user-selected vault directory.
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
DELETE FROM links
WHERE rowid NOT IN (
	SELECT MIN(rowid)
	FROM links
	GROUP BY src_id, dst_id, relation
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_links_unique ON links(src_id, dst_id, relation);
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

func (v *Vault) SetMetaJSON(key string, payload any) error {
	token, err := v.box.encryptJSON(payload)
	if err != nil {
		return err
	}
	_, err = v.DB.Exec(`INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)`, key, token)
	return err
}

func (v *Vault) GetMetaJSON(key string, target any) (bool, error) {
	var token []byte
	err := v.DB.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&token)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := v.box.decryptJSON(token, target); err != nil {
		return false, err
	}
	return true, nil
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

func (v *Vault) DeleteRecord(id string) error {
	if _, err := v.DB.Exec(`DELETE FROM links WHERE src_id = ? OR dst_id = ?`, id, id); err != nil {
		return err
	}
	_, err := v.DB.Exec(`DELETE FROM records WHERE id = ?`, id)
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
	_, err := v.DB.Exec(`INSERT OR IGNORE INTO links(id, src_id, dst_id, relation, created_at) VALUES (?, ?, ?, ?, ?)`, uuid.NewString(), srcID, dstID, relation, utcNow())
	return err
}

func (v *Vault) RemoveLink(srcID, dstID, relation string) error {
	_, err := v.DB.Exec(`DELETE FROM links WHERE src_id = ? AND dst_id = ? AND relation = ?`, srcID, dstID, relation)
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

func (v *Vault) LinkedFrom(dstID, relation string) ([]Record, error) {
	rows, err := v.DB.Query(`SELECT src_id FROM links WHERE dst_id = ? AND relation = ? ORDER BY created_at`, dstID, relation)
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
	data, err := os.ReadFile(path) // #nosec G304 -- importing a user-selected local file is intended behavior.
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
	root, err := os.OpenRoot(v.BlobDir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	file, err := root.OpenFile(id+".bin", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	n, err := file.Write(token)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	if n != len(token) {
		return "", io.ErrShortWrite
	}
	return id, nil
}

func (v *Vault) ExportBlob(id, output string) error {
	plain, err := v.ReadBlob(id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return err
	}
	return os.WriteFile(output, plain, 0o600)
}

func (v *Vault) ReadBlob(id string) ([]byte, error) {
	name, err := blobFileName(id)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(v.BlobDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	token, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return v.box.decrypt(token)
}

func blobFileName(id string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(id))
	parsed, err := uuid.Parse(normalized)
	if err != nil || parsed.String() != normalized {
		return "", fmt.Errorf("invalid blob id")
	}
	return parsed.String() + ".bin", nil
}

func (v *Vault) Search(query string, limit int) ([]SearchHit, error) {
	records, err := v.Records("")
	if err != nil {
		return nil, err
	}
	return convertSearchHits(search.Ranked(searchRecords(records), query, limit)), nil
}

func (v *Vault) SearchByKind(query, kind string, limit int) ([]SearchHit, error) {
	records, err := v.Records(kind)
	if err != nil {
		return nil, err
	}
	return SearchRecords(records, query, limit), nil
}

func (v *Vault) SemanticSearch(query, kind string, limit int) ([]SearchHit, error) {
	records, err := v.Records("")
	if err != nil {
		return nil, err
	}
	index, err := v.semanticIndex(records)
	if err != nil {
		return nil, err
	}
	return convertSearchHits(search.SearchSemanticIndex(index, query, kind, limit)), nil
}

func SearchRecords(records []Record, query string, limit int) []SearchHit {
	return convertSearchHits(search.Ranked(searchRecords(records), query, limit))
}

func SemanticSearchRecords(records []Record, query string, limit int) []SearchHit {
	return convertSearchHits(search.SemanticRanked(searchRecords(records), query, limit))
}

func (v *Vault) semanticIndex(records []Record) ([]search.SemanticDocument, error) {
	fingerprint := semanticFingerprint(records)
	var cache semanticIndexCache
	ok, err := v.GetMetaJSON(semanticIndexMetaKey, &cache)
	if err != nil {
		return nil, err
	}
	if ok && cache.Version == semanticIndexVersion && cache.Fingerprint == fingerprint {
		return cache.Items, nil
	}
	items := search.BuildSemanticIndex(searchRecords(records))
	cache = semanticIndexCache{
		Version:     semanticIndexVersion,
		Fingerprint: fingerprint,
		BuiltAt:     utcNow(),
		Items:       items,
	}
	if err := v.SetMetaJSON(semanticIndexMetaKey, cache); err != nil {
		return nil, err
	}
	return items, nil
}

func semanticFingerprint(records []Record) string {
	parts := make([]string, 0, len(records))
	for _, rec := range records {
		parts = append(parts, rec.Kind+":"+rec.ID+":"+rec.UpdatedAt)
	}
	sort.Strings(parts)
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func searchRecords(records []Record) []search.Record {
	out := make([]search.Record, 0, len(records))
	for _, record := range records {
		out = append(out, search.Record{ID: record.ID, Kind: record.Kind, Payload: record.Payload})
	}
	return out
}

func convertSearchHits(ranked []search.Hit) []SearchHit {
	hits := make([]SearchHit, 0, len(ranked))
	for _, hit := range ranked {
		hits = append(hits, SearchHit{
			Kind:    hit.Kind,
			ID:      hit.ID,
			Title:   hit.Title,
			Excerpt: hit.Excerpt,
			Score:   hit.Score,
		})
	}
	return hits
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
