package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	vaultFormatV2MetaKey = "vault_format_v2"
	vaultFormatV2Version = 2
)

var v2TokenRE = regexp.MustCompile(`[a-z0-9_.:/-]+`)

type VaultFormatV2Meta struct {
	Version       int      `json:"version"`
	MigratedAt    string   `json:"migrated_at"`
	BackupPath    string   `json:"backup_path"`
	Subkeys       []string `json:"subkeys"`
	IndexedFields []string `json:"indexed_fields"`
}

type v2Subkeys struct {
	payload    []byte
	blob       []byte
	metadata   []byte
	blindIndex []byte
}

func (v *Vault) MigrateV2(backupPath string) (string, error) {
	var existing VaultFormatV2Meta
	ok, err := v.GetMetaJSON(vaultFormatV2MetaKey, &existing)
	if err != nil {
		return "", err
	}
	if ok && existing.Version >= vaultFormatV2Version {
		return existing.BackupPath, nil
	}
	if backupPath == "" {
		backupPath = filepath.Join(filepath.Dir(v.Root), "mnemox-v2-backup-"+time.Now().UTC().Format("20060102T150405Z")+".mnemoxbak")
	}
	if err := v.Backup(backupPath); err != nil {
		return "", err
	}
	if err := v.rebuildV2Index(); err != nil {
		return "", err
	}
	meta := VaultFormatV2Meta{
		Version:       vaultFormatV2Version,
		MigratedAt:    utcNow(),
		BackupPath:    backupPath,
		Subkeys:       []string{"payload", "blob", "metadata", "blind-index"},
		IndexedFields: []string{"kind", "status", "tag", "asset", "title", "search"},
	}
	if err := v.SetMetaJSON(vaultFormatV2MetaKey, meta); err != nil {
		return "", err
	}
	return backupPath, nil
}

func (v *Vault) V2SearchCandidateIDs(query string, limit int) ([]string, error) {
	tokens := v2Tokens(query)
	if len(tokens) == 0 {
		return nil, nil
	}
	keys, err := v.deriveV2Subkeys()
	if err != nil {
		return nil, err
	}
	placeholders := make([]string, 0, len(tokens))
	args := make([]any, 0, len(tokens)+2)
	args = append(args, "search")
	for _, token := range tokens {
		placeholders = append(placeholders, "?")
		args = append(args, blindIndexToken(keys.blindIndex, "search", token))
	}
	querySQL := fmt.Sprintf(`SELECT record_id
FROM record_index_v2
WHERE field = ? AND token IN (%s)
GROUP BY record_id
ORDER BY COUNT(*) DESC, record_id
`, strings.Join(placeholders, ",")) // #nosec G201 -- the formatted fragment is only generated "?" placeholders; values stay parameterized.
	if limit > 0 {
		querySQL += "LIMIT ?"
		args = append(args, limit)
	}
	rows, err := v.DB.Query(querySQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (v *Vault) rebuildV2Index() error {
	records, err := v.Records("")
	if err != nil {
		return err
	}
	if _, err := v.DB.Exec(`
CREATE TABLE IF NOT EXISTS record_fields_v2 (
	record_id TEXT NOT NULL,
	field TEXT NOT NULL,
	value BLOB NOT NULL,
	updated_at TEXT NOT NULL,
	PRIMARY KEY(record_id, field)
);
CREATE TABLE IF NOT EXISTS record_index_v2 (
	record_id TEXT NOT NULL,
	field TEXT NOT NULL,
	token BLOB NOT NULL,
	PRIMARY KEY(record_id, field, token)
);
CREATE INDEX IF NOT EXISTS idx_record_index_v2_lookup ON record_index_v2(field, token, record_id);
DELETE FROM record_fields_v2;
DELETE FROM record_index_v2;
`); err != nil {
		return err
	}
	for _, record := range records {
		if err := v.upsertV2Index(record); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) upsertV2Index(record Record) error {
	if !v.v2TablesReady() {
		return nil
	}
	keys, err := v.deriveV2Subkeys()
	if err != nil {
		return err
	}
	fieldBox := &cipherBox{key: keys.metadata}
	fields := v2RecordFields(record)
	tx, err := v.DB.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM record_fields_v2 WHERE record_id = ?`, record.ID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM record_index_v2 WHERE record_id = ?`, record.ID); err != nil {
		_ = tx.Rollback()
		return err
	}
	now := utcNow()
	for field, values := range fields {
		token, err := fieldBox.encryptJSON(values)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO record_fields_v2(record_id, field, value, updated_at) VALUES(?, ?, ?, ?)`, record.ID, field, token, now); err != nil {
			_ = tx.Rollback()
			return err
		}
		for _, value := range values {
			for _, indexToken := range v2FieldTokens(value) {
				if _, err := tx.Exec(`INSERT OR IGNORE INTO record_index_v2(record_id, field, token) VALUES(?, ?, ?)`, record.ID, field, blindIndexToken(keys.blindIndex, field, indexToken)); err != nil {
					_ = tx.Rollback()
					return err
				}
			}
		}
	}
	return tx.Commit()
}

func (v *Vault) deleteV2Index(recordID string) error {
	if !v.v2TablesReady() {
		return nil
	}
	if _, err := v.DB.Exec(`DELETE FROM record_fields_v2 WHERE record_id = ?`, recordID); err != nil {
		return err
	}
	_, err := v.DB.Exec(`DELETE FROM record_index_v2 WHERE record_id = ?`, recordID)
	return err
}

func (v *Vault) v2TablesReady() bool {
	var name string
	err := v.DB.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'record_index_v2'`).Scan(&name)
	return err == nil
}

func (v *Vault) deriveV2Subkeys() (v2Subkeys, error) {
	payload, err := v.deriveV2Subkey("payload")
	if err != nil {
		return v2Subkeys{}, err
	}
	blob, err := v.deriveV2Subkey("blob")
	if err != nil {
		return v2Subkeys{}, err
	}
	metadata, err := v.deriveV2Subkey("metadata")
	if err != nil {
		return v2Subkeys{}, err
	}
	blindIndex, err := v.deriveV2Subkey("blind-index")
	if err != nil {
		return v2Subkeys{}, err
	}
	return v2Subkeys{payload: payload, blob: blob, metadata: metadata, blindIndex: blindIndex}, nil
}

func (v *Vault) deriveV2Subkey(label string) ([]byte, error) {
	reader := hkdf.New(sha256.New, v.box.key, nil, []byte("mnemox:v2:"+label))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func blindIndexToken(key []byte, field, token string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(field))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(normalizeV2Token(token)))
	return mac.Sum(nil)
}

func v2RecordFields(record Record) map[string][]string {
	payload := v2RedactedPayload(record.Kind, record.Payload)
	fields := map[string][]string{}
	add := func(field string, values ...string) {
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value != "" {
				fields[field] = append(fields[field], value)
			}
		}
	}
	add("kind", record.Kind)
	add("title", Title(payload))
	add("status", stringValue(payload["status"]))
	for _, value := range valuesForKeys(payload, "tags") {
		add("tag", value)
	}
	for _, key := range []string{"affected_scope", "asset", "name", "value"} {
		for _, value := range valuesForKeys(payload, key) {
			add("asset", value)
		}
	}
	var searchParts []string
	searchParts = append(searchParts, record.Kind)
	for _, key := range []string{
		"title", "name", "value", "type", "asset", "caption", "summary",
		"technical_details", "impact", "remediation", "validation", "notes", "text", "ocr_text",
		"status", "severity",
	} {
		for _, value := range valuesForKeys(payload, key) {
			searchParts = append(searchParts, value)
		}
	}
	for _, key := range []string{"affected_scope", "tags", "aliases", "references", "open_questions"} {
		searchParts = append(searchParts, valuesForKeys(payload, key)...)
	}
	add("search", strings.Join(searchParts, " "))
	for field := range fields {
		fields[field] = uniqueStrings(fields[field])
	}
	return fields
}

func v2RedactedPayload(kind string, payload map[string]any) map[string]any {
	out := make(map[string]any, len(payload))
	for key, value := range payload {
		if kind == "credential" && key == "secret" {
			continue
		}
		out[key] = value
	}
	return out
}

func valuesForKeys(payload map[string]any, keys ...string) []string {
	var values []string
	for _, key := range keys {
		switch typed := payload[key].(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				values = append(values, typed)
			}
		case []string:
			values = append(values, typed...)
		case []any:
			for _, value := range typed {
				if text := stringValue(value); text != "" {
					values = append(values, text)
				}
			}
		case nil:
		default:
			if text := stringValue(typed); text != "" {
				values = append(values, text)
			}
		}
	}
	return values
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	case nil:
		return ""
	default:
		data, err := json.Marshal(typed)
		if err == nil && string(data) != "null" {
			return strings.Trim(string(data), `"`)
		}
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func v2FieldTokens(value string) []string {
	normalized := normalizeV2Token(value)
	tokens := v2Tokens(value)
	if len(normalized) >= 2 {
		tokens = append(tokens, normalized)
	}
	return uniqueStrings(tokens)
}

func v2Tokens(value string) []string {
	raw := v2TokenRE.FindAllString(strings.ToLower(value), -1)
	out := make([]string, 0, len(raw))
	for _, token := range raw {
		token = normalizeV2Token(token)
		if len(token) >= 2 {
			out = append(out, token)
		}
	}
	return uniqueStrings(out)
}

func normalizeV2Token(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
