package web

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mnemox/internal/cvss"
	"mnemox/internal/domain"
	"mnemox/internal/importer"
	"mnemox/internal/packet"
	"mnemox/internal/vault"
)

//go:embed static
var staticFS embed.FS

type Server struct {
	vaultPath string
	addr      string
	mu        sync.Mutex
	vault     *vault.Vault
	unlocked  bool
}

type Options struct {
	VaultPath string
	Addr      string
}

func New(options Options) *Server {
	if options.VaultPath == "" {
		options.VaultPath = vault.DefaultPath()
	}
	if options.Addr == "" {
		options.Addr = "127.0.0.1:8787"
	}
	return &Server{vaultPath: options.VaultPath, addr: options.Addr}
}

func (s *Server) ListenAndServe() error {
	mux := s.routes()
	server := &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}

func (s *Server) Listen() (net.Listener, error) {
	return net.Listen("tcp", s.addr)
}

func (s *Server) Serve(listener net.Listener) error {
	server := &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.Serve(listener)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("POST /api/init", s.handleInit)
	mux.HandleFunc("POST /api/unlock", s.handleUnlock)
	mux.HandleFunc("POST /api/lock", s.handleLock)
	mux.HandleFunc("GET /api/findings", s.requireUnlock(s.handleListFindings))
	mux.HandleFunc("POST /api/findings", s.requireUnlock(s.handleCreateFinding))
	mux.HandleFunc("GET /api/findings/{id}", s.requireUnlock(s.handleGetFinding))
	mux.HandleFunc("PUT /api/findings/{id}", s.requireUnlock(s.handleUpdateFinding))
	mux.HandleFunc("POST /api/findings/{id}/notes", s.requireUnlock(s.handleAddFindingNote))
	mux.HandleFunc("POST /api/findings/{id}/evidence", s.requireUnlock(s.handleUploadFindingEvidence))
	mux.HandleFunc("POST /api/findings/{id}/cvss", s.requireUnlock(s.handleScoreFinding))
	mux.HandleFunc("GET /api/findings/{id}/packet", s.requireUnlock(s.handleFindingPacket))
	mux.HandleFunc("GET /api/assets", s.requireUnlock(s.handleListAssets))
	mux.HandleFunc("POST /api/assets", s.requireUnlock(s.handleCreateAsset))
	mux.HandleFunc("POST /api/import/nmap", s.requireUnlock(s.handleImportNmap))
	mux.HandleFunc("POST /api/import/nuclei", s.requireUnlock(s.handleImportNuclei))
	mux.HandleFunc("POST /api/import/screenshots", s.requireUnlock(s.handleImportScreenshots))
	mux.HandleFunc("GET /api/evidence", s.requireUnlock(s.handleListEvidence))
	mux.HandleFunc("GET /api/evidence/{id}/download", s.requireUnlock(s.handleDownloadEvidence))
	mux.HandleFunc("GET /api/notes", s.requireUnlock(s.handleListNotes))
	mux.HandleFunc("GET /api/credentials", s.requireUnlock(s.handleListCredentials))
	mux.HandleFunc("POST /api/credentials", s.requireUnlock(s.handleCreateCredential))
	mux.HandleFunc("GET /api/credentials/{id}/secret", s.requireUnlock(s.handleCredentialSecret))
	mux.HandleFunc("GET /api/search", s.requireUnlock(s.handleSearch))
	mux.HandleFunc("GET /api/settings", s.requireUnlock(s.handleSettings))
	mux.Handle("/", spaHandler())
	return secureHeaders(mux)
}

func (s *Server) URL(listener net.Listener) string {
	return "http://" + listener.Addr().String()
}

func (s *Server) requireUnlock(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.currentVault() == nil {
			writeError(w, http.StatusUnauthorized, "vault is locked")
			return
		}
		next(w, r)
	}
}

func (s *Server) currentVault() *vault.Vault {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.vault
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"unlocked":   s.currentVault() != nil,
		"vault_path": s.vaultPath,
	})
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	passphrase := body.Passphrase
	if passphrase == "" {
		passphrase = os.Getenv("MNEMOX_PASSPHRASE")
	}
	if passphrase == "" {
		writeError(w, http.StatusBadRequest, "passphrase is required")
		return
	}
	v, err := vault.OpenWithPassphrase(s.vaultPath, passphrase)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.mu.Lock()
	if s.vault != nil {
		_ = s.vault.Close()
	}
	s.vault = v
	s.unlocked = true
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"unlocked": true})
}

func (s *Server) handleInit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name       string `json:"name"`
		Passphrase string `json:"passphrase"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(body.Passphrase) == "" {
		writeError(w, http.StatusBadRequest, "passphrase is required")
		return
	}
	if body.Name == "" {
		body.Name = "Pentest Engagement"
	}
	v, err := vault.CreateWithPassphrase(s.vaultPath, body.Name, body.Passphrase)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	if s.vault != nil {
		_ = s.vault.Close()
	}
	s.vault = v
	s.unlocked = true
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"unlocked": true})
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.vault != nil {
		_ = s.vault.Close()
	}
	s.vault = nil
	s.unlocked = false
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"unlocked": false})
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	records, err := v.Records("finding")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	counts, _ := v.LinkCounts("has_evidence")
	items := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		item := recordResponse(rec)
		item["evidence_count"] = counts[rec.ID]
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleCreateFinding(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(asString(body["title"])) == "" {
		writeError(w, http.StatusBadRequest, "title is required")
		return
	}
	payload := normalizeFinding(body)
	id, err := s.currentVault().AddRecord("finding", payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rec, _ := s.currentVault().GetRecord(id)
	writeJSON(w, http.StatusCreated, recordResponse(rec))
}

func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	rec, err := v.GetRecord(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	notes, _ := v.Linked(rec.ID, "has_note")
	evidence, _ := v.Linked(rec.ID, "has_evidence")
	response := recordResponse(rec)
	response["notes"] = recordList(notes, false)
	response["evidence"] = recordList(evidence, false)
	markdown, _ := packet.Render(v, rec.ID)
	response["packet_markdown"] = markdown
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleUpdateFinding(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	rec, err := v.GetRecord(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	var body map[string]any
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated := normalizeFinding(body)
	if provided, ok := body["cvss"]; ok && provided != nil {
		updated["cvss"] = provided
	} else if existing, ok := rec.Payload["cvss"]; ok {
		updated["cvss"] = existing
	}
	if err := v.UpdateRecord(rec.ID, updated); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	next, _ := v.GetRecord(rec.ID)
	writeJSON(w, http.StatusOK, recordResponse(next))
}

func (s *Server) handleAddFindingNote(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text  string   `json:"text"`
		Asset string   `json:"asset"`
		Tags  []string `json:"tags"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(body.Text) == "" {
		writeError(w, http.StatusBadRequest, "text is required")
		return
	}
	v := s.currentVault()
	if _, err := v.GetRecord(r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	id, err := v.AddRecord("note", map[string]any{"text": body.Text, "asset": body.Asset, "tags": body.Tags})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := v.AddLink(r.PathValue("id"), id, "has_note"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rec, _ := v.GetRecord(id)
	writeJSON(w, http.StatusCreated, recordResponse(rec))
}

func (s *Server) handleUploadFindingEvidence(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	v := s.currentVault()
	if _, err := v.GetRecord(r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	blobID, err := v.StoreBlobBytes(data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	kind := r.FormValue("kind")
	if kind == "" {
		kind = "file"
	}
	id, err := v.AddRecord("evidence", map[string]any{
		"kind":          kind,
		"caption":       r.FormValue("caption"),
		"original_path": header.Filename,
		"blob_id":       blobID,
		"tags":          splitCSV(r.FormValue("tags")),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := v.AddLink(r.PathValue("id"), id, "has_evidence"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rec, _ := v.GetRecord(id)
	writeJSON(w, http.StatusCreated, recordResponse(rec))
}

func (s *Server) handleScoreFinding(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vector  string            `json:"vector"`
		Metrics map[string]string `json:"metrics"`
		Notes   string            `json:"notes"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var result cvss.Result
	var err error
	if body.Vector != "" {
		result, err = cvss.FromVector(body.Vector)
	} else {
		result, err = cvss.FromMetrics(body.Metrics)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	v := s.currentVault()
	rec, err := v.GetRecord(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	rec.Payload["cvss"] = map[string]any{
		"vector":   result.Vector,
		"score":    result.Score,
		"severity": result.Severity,
		"metrics":  result.Metrics,
		"notes":    body.Notes,
	}
	if severity := asString(rec.Payload["severity"]); severity == "" || severity == "Unscored" {
		rec.Payload["severity"] = result.Severity
	}
	if err := v.UpdateRecord(rec.ID, rec.Payload); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rec.Payload["cvss"])
}

func (s *Server) handleFindingPacket(w http.ResponseWriter, r *http.Request) {
	markdown, err := packet.Render(s.currentVault(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="finding-packet.md"`)
		_, _ = w.Write([]byte(markdown))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"markdown": markdown})
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	records, err := s.currentVault().Records("asset")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": recordList(records, false)})
}

func (s *Server) handleCreateAsset(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := asString(body["name"])
	if strings.TrimSpace(name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	value := asString(body["value"])
	if value == "" {
		value = name
	}
	id, err := s.currentVault().AddRecord("asset", domain.AssetPayload(domain.Asset{
		Name:  name,
		Type:  asString(body["type"]),
		Value: value,
		Tags:  asStringSlice(body["tags"]),
		Notes: asString(body["notes"]),
	}))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rec, _ := s.currentVault().GetRecord(id)
	writeJSON(w, http.StatusCreated, recordResponse(rec))
}

func (s *Server) handleImportNmap(w http.ResponseWriter, r *http.Request) {
	s.handleImportFile(w, r, importer.NmapXML)
}

func (s *Server) handleImportNuclei(w http.ResponseWriter, r *http.Request) {
	s.handleImportFile(w, r, importer.NucleiJSON)
}

func (s *Server) handleImportScreenshots(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path string `json:"path"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := importer.ScreenshotFolder(s.currentVault(), body.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleImportFile(w http.ResponseWriter, r *http.Request, fn func(*vault.Vault, string) (importer.Result, error)) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()
	temp, err := os.CreateTemp("", "mnemox-import-*"+filepath.Ext(header.Filename))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.Remove(temp.Name())
	if _, err := io.Copy(temp, file); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		_ = temp.Close()
		return
	}
	_ = temp.Close()
	result, err := fn(s.currentVault(), temp.Name())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleListEvidence(w http.ResponseWriter, r *http.Request) {
	records, err := s.currentVault().Records("evidence")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": recordList(records, false)})
}

func (s *Server) handleDownloadEvidence(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	rec, err := v.GetRecord(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	blobID := asString(rec.Payload["blob_id"])
	if blobID == "" {
		writeError(w, http.StatusNotFound, "evidence has no blob")
		return
	}
	data, err := v.ReadBlob(blobID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	filename := filepath.Base(asString(rec.Payload["original_path"]))
	if filename == "." || filename == "/" || filename == "" {
		filename = "evidence.bin"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
	_, _ = w.Write(data)
}

func (s *Server) handleListNotes(w http.ResponseWriter, r *http.Request) {
	records, err := s.currentVault().Records("note")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": recordList(records, false)})
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	records, err := s.currentVault().Records("credential")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": recordList(records, true)})
}

func (s *Server) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(asString(body["name"])) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	id, err := s.currentVault().AddRecord("credential", map[string]any{
		"name":     asString(body["name"]),
		"username": asString(body["username"]),
		"secret":   asString(body["secret"]),
		"scope":    asString(body["scope"]),
		"tags":     asStringSlice(body["tags"]),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rec, _ := s.currentVault().GetRecord(id)
	writeJSON(w, http.StatusCreated, sanitizeRecord(rec, true))
}

func (s *Server) handleCredentialSecret(w http.ResponseWriter, r *http.Request) {
	rec, err := s.currentVault().GetRecord(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if rec.Kind != "credential" {
		writeError(w, http.StatusBadRequest, "record is not a credential")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": asString(rec.Payload["secret"])})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	limit := 20
	hits, err := s.currentVault().Search(query, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range hits {
		if hits[i].Kind == "credential" {
			hits[i].Excerpt = redactSecretFragments(hits[i].Excerpt)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": hits})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"vault_path": s.vaultPath,
		"server":     s.addr,
		"unlocked":   s.currentVault() != nil,
	})
}

func spaHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(filepath.Clean(r.URL.Path), "/")
		if path == "." || path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(sub, path); err != nil {
			r.URL.Path = "/index.html"
		}
		files.ServeHTTP(w, r)
	})
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func readJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}

func recordList(records []vault.Record, redactCredential bool) []map[string]any {
	items := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		items = append(items, sanitizeRecord(rec, redactCredential))
	}
	return items
}

func recordResponse(rec vault.Record) map[string]any {
	return sanitizeRecord(rec, false)
}

func sanitizeRecord(rec vault.Record, redactCredential bool) map[string]any {
	payload := cloneMap(rec.Payload)
	if redactCredential && rec.Kind == "credential" {
		delete(payload, "secret")
		payload["has_secret"] = true
	}
	return map[string]any{
		"id":         rec.ID,
		"kind":       rec.Kind,
		"created_at": rec.CreatedAt,
		"updated_at": rec.UpdatedAt,
		"payload":    payload,
	}
}

func normalizeFinding(body map[string]any) map[string]any {
	return map[string]any{
		"title":             asString(body["title"]),
		"status":            defaultString(asString(body["status"]), "draft"),
		"severity":          defaultString(asString(body["severity"]), "Unscored"),
		"affected_scope":    asStringSlice(body["affected_scope"]),
		"summary":           asString(body["summary"]),
		"technical_details": asString(body["technical_details"]),
		"impact":            asString(body["impact"]),
		"remediation":       asString(body["remediation"]),
		"validation":        asString(body["validation"]),
		"references":        asStringSlice(body["references"]),
		"open_questions":    asStringSlice(body["open_questions"]),
	}
}

func cloneMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func asStringSlice(v any) []string {
	switch typed := v.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s := strings.TrimSpace(fmt.Sprint(item)); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		return splitCSV(typed)
	default:
		return []string{}
	}
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func redactSecretFragments(value string) string {
	if value == "" {
		return value
	}
	replacer := strings.NewReplacer("secret", "redacted")
	return replacer.Replace(value)
}

func init() {
	_ = mime.AddExtensionType(".js", "text/javascript; charset=utf-8")
}

var errNonLocalBind = errors.New("non-local bind addresses require --allow-remote")
