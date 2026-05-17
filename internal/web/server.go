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
	"sort"
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
	mux.HandleFunc("POST /api/findings/{id}/assets", s.requireUnlock(s.handleLinkFindingAsset))
	mux.HandleFunc("DELETE /api/findings/{id}/assets/{asset_id}", s.requireUnlock(s.handleUnlinkFindingAsset))
	mux.HandleFunc("POST /api/findings/{id}/notes", s.requireUnlock(s.handleAddFindingNote))
	mux.HandleFunc("POST /api/findings/{id}/evidence", s.requireUnlock(s.handleUploadFindingEvidence))
	mux.HandleFunc("POST /api/findings/{id}/cvss", s.requireUnlock(s.handleScoreFinding))
	mux.HandleFunc("GET /api/findings/{id}/packet", s.requireUnlock(s.handleFindingPacket))
	mux.HandleFunc("GET /api/findings/{id}/citation-bundle", s.requireUnlock(s.handleCitationBundle))
	mux.HandleFunc("GET /api/assets", s.requireUnlock(s.handleListAssets))
	mux.HandleFunc("POST /api/assets", s.requireUnlock(s.handleCreateAsset))
	mux.HandleFunc("GET /api/assets/duplicates", s.requireUnlock(s.handleAssetDuplicates))
	mux.HandleFunc("GET /api/assets/{id}", s.requireUnlock(s.handleGetAsset))
	mux.HandleFunc("POST /api/assets/{id}/merge", s.requireUnlock(s.handleMergeAsset))
	mux.HandleFunc("POST /api/import/nmap", s.requireUnlock(s.handleImportNmap))
	mux.HandleFunc("POST /api/import/nuclei", s.requireUnlock(s.handleImportNuclei))
	mux.HandleFunc("POST /api/import/burp", s.requireUnlock(s.handleImportBurp))
	mux.HandleFunc("POST /api/import/nessus", s.requireUnlock(s.handleImportNessus))
	mux.HandleFunc("POST /api/import/bloodhound", s.requireUnlock(s.handleImportBloodHound))
	mux.HandleFunc("POST /api/import/screenshots", s.requireUnlock(s.handleImportScreenshots))
	mux.HandleFunc("GET /api/evidence", s.requireUnlock(s.handleListEvidence))
	mux.HandleFunc("PUT /api/evidence/{id}", s.requireUnlock(s.handleUpdateEvidence))
	mux.HandleFunc("GET /api/evidence/{id}/download", s.requireUnlock(s.handleDownloadEvidence))
	mux.HandleFunc("GET /api/evidence/{id}/preview", s.requireUnlock(s.handlePreviewEvidence))
	mux.HandleFunc("POST /api/evidence/{id}/assets", s.requireUnlock(s.handleLinkEvidenceAsset))
	mux.HandleFunc("DELETE /api/evidence/{id}/assets/{asset_id}", s.requireUnlock(s.handleUnlinkEvidenceAsset))
	mux.HandleFunc("GET /api/notes", s.requireUnlock(s.handleListNotes))
	mux.HandleFunc("PUT /api/notes/{id}", s.requireUnlock(s.handleUpdateNote))
	mux.HandleFunc("POST /api/notes/{id}/assets", s.requireUnlock(s.handleLinkNoteAsset))
	mux.HandleFunc("DELETE /api/notes/{id}/assets/{asset_id}", s.requireUnlock(s.handleUnlinkNoteAsset))
	mux.HandleFunc("GET /api/credentials", s.requireUnlock(s.handleListCredentials))
	mux.HandleFunc("POST /api/credentials", s.requireUnlock(s.handleCreateCredential))
	mux.HandleFunc("PUT /api/credentials/{id}", s.requireUnlock(s.handleUpdateCredential))
	mux.HandleFunc("GET /api/credentials/{id}/secret", s.requireUnlock(s.handleCredentialSecret))
	mux.HandleFunc("POST /api/credentials/{id}/assets", s.requireUnlock(s.handleLinkCredentialAsset))
	mux.HandleFunc("DELETE /api/credentials/{id}/assets/{asset_id}", s.requireUnlock(s.handleUnlinkCredentialAsset))
	mux.HandleFunc("GET /api/attack-paths", s.requireUnlock(s.handleAttackPaths))
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
	var records []vault.Record
	var err error
	if assetID := r.URL.Query().Get("asset_id"); assetID != "" {
		records, err = v.LinkedFrom(assetID, "affects_asset")
	} else {
		records, err = v.Records("finding")
	}
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
	assets, _ := v.Linked(rec.ID, "affects_asset")
	response := recordResponse(rec)
	response["notes"] = recordList(notes, false)
	response["evidence"] = recordList(evidence, false)
	response["assets"] = recordList(assets, false)
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

func (s *Server) handleLinkFindingAsset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AssetID string `json:"asset_id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.linkTypedRecords(r.PathValue("id"), body.AssetID, "finding", "asset", "affects_asset"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	assets, _ := s.currentVault().Linked(r.PathValue("id"), "affects_asset")
	writeJSON(w, http.StatusOK, map[string]any{"items": recordList(assets, false)})
}

func (s *Server) handleUnlinkFindingAsset(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	if err := v.RemoveLink(r.PathValue("id"), r.PathValue("asset_id"), "affects_asset"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	assets, _ := v.Linked(r.PathValue("id"), "affects_asset")
	writeJSON(w, http.StatusOK, map[string]any{"items": recordList(assets, false)})
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
	if assetID := s.assetIDByNameOrValue(body.Asset); assetID != "" {
		_ = v.AddLink(id, assetID, "note_asset")
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
	assets, _ := v.Linked(r.PathValue("id"), "affects_asset")
	for _, asset := range assets {
		_ = v.AddLink(id, asset.ID, "evidence_asset")
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

func (s *Server) handleCitationBundle(w http.ResponseWriter, r *http.Request) {
	markdown, err := packet.RenderCitationBundle(s.currentVault(), r.PathValue("id"), packet.CitationBundleOptions{
		AssetID: r.URL.Query().Get("asset_id"),
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="evidence-citation-bundle.md"`)
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

func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	rec, err := v.GetRecord(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if rec.Kind != "asset" {
		writeError(w, http.StatusBadRequest, "record is not an asset")
		return
	}
	writeJSON(w, http.StatusOK, assetDetailResponse(v, rec))
}

func (s *Server) handleAssetDuplicates(w http.ResponseWriter, r *http.Request) {
	groups, err := assetDuplicateGroups(s.currentVault())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": groups})
}

func (s *Server) handleMergeAsset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DuplicateID string `json:"duplicate_id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(body.DuplicateID) == "" {
		writeError(w, http.StatusBadRequest, "duplicate_id is required")
		return
	}
	detail, err := mergeAssetRecords(s.currentVault(), r.PathValue("id"), body.DuplicateID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) handleImportNmap(w http.ResponseWriter, r *http.Request) {
	s.handleImportFile(w, r, importer.NmapXML)
}

func (s *Server) handleImportNuclei(w http.ResponseWriter, r *http.Request) {
	s.handleImportFile(w, r, importer.NucleiJSON)
}

func (s *Server) handleImportBurp(w http.ResponseWriter, r *http.Request) {
	s.handleImportFile(w, r, importer.BurpXML)
}

func (s *Server) handleImportNessus(w http.ResponseWriter, r *http.Request) {
	s.handleImportFile(w, r, importer.NessusXML)
}

func (s *Server) handleImportBloodHound(w http.ResponseWriter, r *http.Request) {
	s.handleImportFile(w, r, importer.BloodHoundJSON)
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
	v := s.currentVault()
	records, err := v.Records("evidence")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": recordListWithAssets(v, records, false, "evidence_asset")})
}

func (s *Server) handleUpdateEvidence(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	rec, err := v.GetRecord(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if rec.Kind != "evidence" {
		writeError(w, http.StatusBadRequest, "record is not evidence")
		return
	}
	var body map[string]any
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	next := cloneMap(rec.Payload)
	for _, key := range []string{"kind", "caption", "original_path"} {
		if _, ok := body[key]; ok {
			next[key] = asString(body[key])
		}
	}
	if _, ok := body["tags"]; ok {
		next["tags"] = asStringSlice(body["tags"])
	}
	if err := v.UpdateRecord(rec.ID, next); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated, _ := v.GetRecord(rec.ID)
	response := recordResponse(updated)
	assets, _ := v.Linked(updated.ID, "evidence_asset")
	response["assets"] = recordList(assets, false)
	writeJSON(w, http.StatusOK, response)
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

func (s *Server) handlePreviewEvidence(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	rec, err := v.GetRecord(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if rec.Kind != "evidence" {
		writeError(w, http.StatusBadRequest, "record is not evidence")
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
	contentType := http.DetectContentType(data)
	if !strings.HasPrefix(contentType, "image/") {
		writeError(w, http.StatusUnsupportedMediaType, "evidence preview is only available for images")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *Server) handleLinkEvidenceAsset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AssetID string `json:"asset_id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.linkTypedRecords(r.PathValue("id"), body.AssetID, "evidence", "asset", "evidence_asset"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	assets, _ := s.currentVault().Linked(r.PathValue("id"), "evidence_asset")
	writeJSON(w, http.StatusOK, map[string]any{"items": recordList(assets, false)})
}

func (s *Server) handleUnlinkEvidenceAsset(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	if err := v.RemoveLink(r.PathValue("id"), r.PathValue("asset_id"), "evidence_asset"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	assets, _ := v.Linked(r.PathValue("id"), "evidence_asset")
	writeJSON(w, http.StatusOK, map[string]any{"items": recordList(assets, false)})
}

func (s *Server) handleListNotes(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	records, err := v.Records("note")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": recordListWithAssets(v, records, false, "note_asset")})
}

func (s *Server) handleUpdateNote(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	rec, err := v.GetRecord(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if rec.Kind != "note" {
		writeError(w, http.StatusBadRequest, "record is not a note")
		return
	}
	var body map[string]any
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	next := cloneMap(rec.Payload)
	for _, key := range []string{"text", "asset"} {
		if _, ok := body[key]; ok {
			next[key] = asString(body[key])
		}
	}
	if _, ok := body["tags"]; ok {
		next["tags"] = asStringSlice(body["tags"])
	}
	if strings.TrimSpace(asString(next["text"])) == "" {
		writeError(w, http.StatusBadRequest, "text is required")
		return
	}
	if err := v.UpdateRecord(rec.ID, next); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if assetID := s.assetIDByNameOrValue(asString(next["asset"])); assetID != "" {
		_ = v.AddLink(rec.ID, assetID, "note_asset")
	}
	updated, _ := v.GetRecord(rec.ID)
	response := recordResponse(updated)
	assets, _ := v.Linked(updated.ID, "note_asset")
	response["assets"] = recordList(assets, false)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleLinkNoteAsset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AssetID string `json:"asset_id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.linkTypedRecords(r.PathValue("id"), body.AssetID, "note", "asset", "note_asset"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	assets, _ := s.currentVault().Linked(r.PathValue("id"), "note_asset")
	writeJSON(w, http.StatusOK, map[string]any{"items": recordList(assets, false)})
}

func (s *Server) handleUnlinkNoteAsset(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	if err := v.RemoveLink(r.PathValue("id"), r.PathValue("asset_id"), "note_asset"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	assets, _ := v.Linked(r.PathValue("id"), "note_asset")
	writeJSON(w, http.StatusOK, map[string]any{"items": recordList(assets, false)})
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	records, err := v.Records("credential")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": recordListWithAssets(v, records, true, "credential_asset")})
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

func (s *Server) handleUpdateCredential(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	rec, err := v.GetRecord(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if rec.Kind != "credential" {
		writeError(w, http.StatusBadRequest, "record is not a credential")
		return
	}
	var body map[string]any
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	next := cloneMap(rec.Payload)
	for _, key := range []string{"name", "username", "scope"} {
		if _, ok := body[key]; ok {
			next[key] = asString(body[key])
		}
	}
	if _, ok := body["tags"]; ok {
		next["tags"] = asStringSlice(body["tags"])
	}
	if secret, ok := body["secret"]; ok && strings.TrimSpace(asString(secret)) != "" {
		next["secret"] = asString(secret)
	}
	if strings.TrimSpace(asString(next["name"])) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := v.UpdateRecord(rec.ID, next); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated, _ := v.GetRecord(rec.ID)
	response := sanitizeRecord(updated, true)
	assets, _ := v.Linked(updated.ID, "credential_asset")
	response["assets"] = recordList(assets, false)
	writeJSON(w, http.StatusOK, response)
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

func (s *Server) handleLinkCredentialAsset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AssetID string `json:"asset_id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.linkTypedRecords(r.PathValue("id"), body.AssetID, "credential", "asset", "credential_asset"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	assets, _ := s.currentVault().Linked(r.PathValue("id"), "credential_asset")
	writeJSON(w, http.StatusOK, map[string]any{"items": recordList(assets, false)})
}

func (s *Server) handleUnlinkCredentialAsset(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	if err := v.RemoveLink(r.PathValue("id"), r.PathValue("asset_id"), "credential_asset"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	assets, _ := v.Linked(r.PathValue("id"), "credential_asset")
	writeJSON(w, http.StatusOK, map[string]any{"items": recordList(assets, false)})
}

func (s *Server) handleAttackPaths(w http.ResponseWriter, r *http.Request) {
	v := s.currentVault()
	assets, err := v.Records("asset")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	items := make([]map[string]any, 0, len(assets))
	for _, asset := range assets {
		findings, _ := v.LinkedFrom(asset.ID, "affects_asset")
		evidence, _ := v.LinkedFrom(asset.ID, "evidence_asset")
		notes, _ := v.LinkedFrom(asset.ID, "note_asset")
		credentials, _ := v.LinkedFrom(asset.ID, "credential_asset")
		if len(findings)+len(evidence)+len(notes)+len(credentials) == 0 {
			continue
		}
		checks := attackPathChecks(v, asset, findings, evidence, notes, credentials)
		item := recordResponse(asset)
		item["findings"] = recordList(findings, false)
		item["evidence"] = recordList(evidence, false)
		item["notes"] = recordList(notes, false)
		item["credentials"] = recordList(credentials, true)
		item["risk_score"] = attackPathRisk(findings, evidence, credentials)
		item["checks"] = checks
		item["packet_markdown"] = attackPathPacket(asset, findings, evidence, notes, credentials, checks)
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		left, _ := items[i]["risk_score"].(int)
		right, _ := items[j]["risk_score"].(int)
		if left == right {
			return asString(items[i]["id"]) < asString(items[j]["id"])
		}
		return left > right
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	kind := r.URL.Query().Get("kind")
	assetID := r.URL.Query().Get("asset_id")
	mode := r.URL.Query().Get("mode")
	limit := 20
	v := s.currentVault()
	var hits []vault.SearchHit
	var err error
	if assetID != "" {
		records, collectErr := s.assetRelatedRecords(assetID, kind)
		if collectErr != nil {
			writeError(w, http.StatusBadRequest, collectErr.Error())
			return
		}
		hits = searchRecordHits(records, query, mode, limit)
	} else if kind != "" && kind != "all" {
		if mode == "semantic" {
			hits, err = v.SemanticSearch(query, kind, limit)
		} else {
			hits, err = v.SearchByKind(query, kind, limit)
		}
	} else {
		if mode == "semantic" {
			hits, err = v.SemanticSearch(query, "", limit)
		} else {
			hits, err = v.Search(query, limit)
		}
	}
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

func (s *Server) linkTypedRecords(srcID, dstID, srcKind, dstKind, relation string) error {
	v := s.currentVault()
	src, err := v.GetRecord(srcID)
	if err != nil {
		return err
	}
	if src.Kind != srcKind {
		return fmt.Errorf("source record is %s, expected %s", src.Kind, srcKind)
	}
	dst, err := v.GetRecord(dstID)
	if err != nil {
		return err
	}
	if dst.Kind != dstKind {
		return fmt.Errorf("target record is %s, expected %s", dst.Kind, dstKind)
	}
	return v.AddLink(srcID, dstID, relation)
}

func mergeAssetRecords(v *vault.Vault, primaryID, duplicateID string) (map[string]any, error) {
	if primaryID == duplicateID {
		return nil, fmt.Errorf("cannot merge an asset into itself")
	}
	primary, err := v.GetRecord(primaryID)
	if err != nil {
		return nil, err
	}
	if primary.Kind != "asset" {
		return nil, fmt.Errorf("primary record is not an asset")
	}
	duplicate, err := v.GetRecord(duplicateID)
	if err != nil {
		return nil, err
	}
	if duplicate.Kind != "asset" {
		return nil, fmt.Errorf("duplicate record is not an asset")
	}

	for _, rel := range assetLinkRelations() {
		linked, err := v.LinkedFrom(duplicateID, rel)
		if err != nil {
			return nil, err
		}
		for _, rec := range linked {
			if err := v.AddLink(rec.ID, primaryID, rel); err != nil {
				return nil, err
			}
			if err := v.RemoveLink(rec.ID, duplicateID, rel); err != nil {
				return nil, err
			}
		}
	}

	payload := mergedAssetPayload(primary.Payload, duplicate.Payload)
	if err := v.UpdateRecord(primaryID, payload); err != nil {
		return nil, err
	}
	if err := v.DeleteRecord(duplicateID); err != nil {
		return nil, err
	}
	updated, err := v.GetRecord(primaryID)
	if err != nil {
		return nil, err
	}
	return assetDetailResponse(v, updated), nil
}

func assetDetailResponse(v *vault.Vault, rec vault.Record) map[string]any {
	findings, _ := v.LinkedFrom(rec.ID, "affects_asset")
	evidence, _ := v.LinkedFrom(rec.ID, "evidence_asset")
	notes, _ := v.LinkedFrom(rec.ID, "note_asset")
	credentials, _ := v.LinkedFrom(rec.ID, "credential_asset")
	response := recordResponse(rec)
	response["findings"] = recordList(findings, false)
	response["evidence"] = recordList(evidence, false)
	response["notes"] = recordList(notes, false)
	response["credentials"] = recordList(credentials, true)
	return response
}

func assetDuplicateGroups(v *vault.Vault) ([]map[string]any, error) {
	assets, err := v.Records("asset")
	if err != nil {
		return nil, err
	}
	type candidate struct {
		reason string
		items  []vault.Record
	}
	candidates := map[string]candidate{}
	for _, asset := range assets {
		keys := assetDuplicateKeys(asset)
		for _, key := range keys {
			entry := candidates[key.key]
			entry.reason = key.reason
			entry.items = append(entry.items, asset)
			candidates[key.key] = entry
		}
	}
	groups := []map[string]any{}
	for key, entry := range candidates {
		if len(entry.items) < 2 {
			continue
		}
		groups = append(groups, map[string]any{
			"signature": key,
			"reason":    entry.reason,
			"items":     assetRecordsWithRelationCounts(v, entry.items),
		})
	}
	return groups, nil
}

type assetDuplicateKey struct {
	key    string
	reason string
}

func assetDuplicateKeys(asset vault.Record) []assetDuplicateKey {
	assetType := normalizeAssetValue(asString(asset.Payload["type"]))
	name := normalizeAssetValue(asString(asset.Payload["name"]))
	value := normalizeAssetValue(asString(asset.Payload["value"]))
	var keys []assetDuplicateKey
	if assetType != "" && value != "" {
		keys = append(keys, assetDuplicateKey{key: "type-value:" + assetType + ":" + value, reason: "same type and value"})
	}
	if name != "" {
		keys = append(keys, assetDuplicateKey{key: "name:" + name, reason: "same name"})
	}
	if value != "" && name != value {
		keys = append(keys, assetDuplicateKey{key: "name:" + value, reason: "value matches another asset name"})
	}
	return keys
}

func assetRecordsWithRelationCounts(v *vault.Vault, records []vault.Record) []map[string]any {
	items := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		item := recordResponse(rec)
		total := 0
		for _, rel := range assetLinkRelations() {
			linked, _ := v.LinkedFrom(rec.ID, rel)
			total += len(linked)
		}
		item["relation_count"] = total
		items = append(items, item)
	}
	return items
}

func assetLinkRelations() []string {
	return []string{"affects_asset", "evidence_asset", "note_asset", "credential_asset"}
}

func mergedAssetPayload(primary, duplicate map[string]any) map[string]any {
	payload := cloneMap(primary)
	for _, key := range []string{"name", "type", "value"} {
		if strings.TrimSpace(asString(payload[key])) == "" {
			payload[key] = asString(duplicate[key])
		}
	}
	payload["tags"] = mergeStringSlices(asStringSlice(primary["tags"]), asStringSlice(duplicate["tags"]))
	payload["aliases"] = mergeStringSlices(
		asStringSlice(primary["aliases"]),
		asStringSlice(duplicate["aliases"]),
		[]string{asString(duplicate["name"]), asString(duplicate["value"])},
	)
	payload["notes"] = mergedNotes(asString(primary["notes"]), asString(duplicate["notes"]), asString(duplicate["name"]), asString(duplicate["value"]))
	return payload
}

func mergedNotes(primaryNotes, duplicateNotes, duplicateName, duplicateValue string) string {
	primaryNotes = strings.TrimSpace(primaryNotes)
	duplicateNotes = strings.TrimSpace(duplicateNotes)
	if duplicateNotes == "" {
		return primaryNotes
	}
	source := strings.TrimSpace(strings.Join([]string{duplicateName, duplicateValue}, " "))
	if source == "" {
		source = "merged asset"
	}
	merged := "Merged from " + source + ":\n" + duplicateNotes
	if primaryNotes == "" {
		return merged
	}
	return primaryNotes + "\n\n" + merged
}

func mergeStringSlices(groups ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range groups {
		for _, value := range group {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			key := strings.ToLower(value)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, value)
		}
	}
	return out
}

func normalizeAssetValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (s *Server) assetRelatedRecords(assetID, kind string) ([]vault.Record, error) {
	v := s.currentVault()
	asset, err := v.GetRecord(assetID)
	if err != nil {
		return nil, err
	}
	if asset.Kind != "asset" {
		return nil, fmt.Errorf("record is not an asset")
	}
	type relation struct {
		kind string
		name string
	}
	relations := []relation{
		{kind: "finding", name: "affects_asset"},
		{kind: "evidence", name: "evidence_asset"},
		{kind: "note", name: "note_asset"},
		{kind: "credential", name: "credential_asset"},
	}
	if kind == "" || kind == "all" || kind == "asset" {
		relations = append([]relation{{kind: "asset", name: ""}}, relations...)
	}
	var out []vault.Record
	for _, rel := range relations {
		if kind != "" && kind != "all" && kind != rel.kind {
			continue
		}
		if rel.kind == "asset" {
			out = append(out, asset)
			continue
		}
		records, err := v.LinkedFrom(assetID, rel.name)
		if err != nil {
			return nil, err
		}
		out = append(out, records...)
	}
	return out, nil
}

func (s *Server) assetIDByNameOrValue(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	assets, err := s.currentVault().Records("asset")
	if err != nil {
		return ""
	}
	for _, asset := range assets {
		name := strings.ToLower(asString(asset.Payload["name"]))
		assetValue := strings.ToLower(asString(asset.Payload["value"]))
		if value == name || value == assetValue {
			return asset.ID
		}
	}
	return ""
}

func searchRecordHits(records []vault.Record, query, mode string, limit int) []vault.SearchHit {
	if strings.TrimSpace(query) != "" {
		if mode == "semantic" {
			return vault.SemanticSearchRecords(records, query, limit)
		}
		return vault.SearchRecords(records, query, limit)
	}
	hits := make([]vault.SearchHit, 0, len(records))
	for _, rec := range records {
		excerpt := relationshipExcerpt(rec)
		if rec.Kind == "credential" {
			excerpt = redactSecretFragments(excerpt)
		}
		hits = append(hits, vault.SearchHit{
			Kind:    rec.Kind,
			ID:      rec.ID,
			Title:   vault.Title(rec.Payload),
			Excerpt: excerpt,
			Score:   0,
		})
	}
	if limit > 0 && len(hits) > limit {
		return hits[:limit]
	}
	return hits
}

func attackPathRisk(findings, evidence, credentials []vault.Record) int {
	score := len(evidence) + len(credentials)*2
	for _, finding := range findings {
		switch strings.ToUpper(asString(finding.Payload["severity"])) {
		case "CRITICAL":
			score += 5
		case "HIGH":
			score += 4
		case "MEDIUM":
			score += 3
		case "LOW":
			score += 2
		default:
			score++
		}
	}
	return score
}

func attackPathChecks(v *vault.Vault, asset vault.Record, findings, evidence, notes, credentials []vault.Record) []string {
	var checks []string
	if len(findings) == 0 {
		checks = append(checks, "No findings linked to "+vault.Title(asset.Payload)+".")
	}
	if len(evidence) == 0 {
		checks = append(checks, "No evidence linked to "+vault.Title(asset.Payload)+".")
	}
	for _, finding := range findings {
		linkedEvidence, _ := v.Linked(finding.ID, "has_evidence")
		if len(linkedEvidence) == 0 {
			checks = append(checks, "Finding has no direct evidence: "+vault.Title(finding.Payload)+".")
		}
		if strings.EqualFold(asString(finding.Payload["severity"]), "Critical") || strings.EqualFold(asString(finding.Payload["severity"]), "High") {
			if len(linkedEvidence) == 0 {
				checks = append(checks, "High-impact finding needs evidence before reporting: "+vault.Title(finding.Payload)+".")
			}
		}
	}
	for _, item := range evidence {
		if strings.TrimSpace(asString(item.Payload["caption"])) == "" {
			checks = append(checks, "Evidence is missing a caption: "+vault.Title(item.Payload)+".")
		}
	}
	if len(credentials) > 0 && len(findings) == 0 {
		checks = append(checks, "Credential context exists without a linked finding.")
	}
	if len(checks) == 0 {
		checks = append(checks, "Linked context is ready for an attack path packet.")
	}
	return checks
}

func attackPathPacket(asset vault.Record, findings, evidence, notes, credentials []vault.Record, checks []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Attack Path: %s\n\n", vault.Title(asset.Payload))
	fmt.Fprintf(&b, "## Asset\n\n- Name: %s\n- Type: %s\n- Value: %s\n- Risk Score: %d\n\n",
		vault.Title(asset.Payload),
		defaultString(asString(asset.Payload["type"]), "asset"),
		asString(asset.Payload["value"]),
		attackPathRisk(findings, evidence, credentials),
	)
	writeAttackPathRecords(&b, "Findings", findings)
	writeAttackPathRecords(&b, "Evidence", evidence)
	writeAttackPathRecords(&b, "Notes", notes)
	writeAttackPathRecords(&b, "Credential Context", credentials)
	b.WriteString("## Completeness Checks\n\n")
	for _, check := range checks {
		fmt.Fprintf(&b, "- %s\n", check)
	}
	return strings.TrimSpace(b.String()) + "\n"
}

func writeAttackPathRecords(b *strings.Builder, title string, records []vault.Record) {
	fmt.Fprintf(b, "## %s\n\n", title)
	if len(records) == 0 {
		b.WriteString("- None\n\n")
		return
	}
	for _, rec := range records {
		fmt.Fprintf(b, "- [%s:%s] %s", rec.Kind, shortRecordID(rec.ID), vault.Title(rec.Payload))
		if summary := relationshipExcerpt(rec); summary != "" {
			fmt.Fprintf(b, " - %s", redactSecretFragments(summary))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func shortRecordID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func relationshipExcerpt(rec vault.Record) string {
	switch rec.Kind {
	case "finding":
		return strings.TrimSpace(strings.Join([]string{
			asString(rec.Payload["severity"]),
			asString(rec.Payload["status"]),
			asString(rec.Payload["summary"]),
		}, " "))
	case "evidence":
		return strings.TrimSpace(strings.Join([]string{
			asString(rec.Payload["kind"]),
			asString(rec.Payload["caption"]),
			asString(rec.Payload["original_path"]),
		}, " "))
	case "credential":
		return strings.TrimSpace(strings.Join([]string{
			asString(rec.Payload["username"]),
			asString(rec.Payload["scope"]),
		}, " "))
	case "asset":
		return strings.TrimSpace(strings.Join([]string{
			asString(rec.Payload["type"]),
			asString(rec.Payload["value"]),
			asString(rec.Payload["notes"]),
		}, " "))
	default:
		return vault.Title(rec.Payload)
	}
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

func recordListWithAssets(v *vault.Vault, records []vault.Record, redactCredential bool, relation string) []map[string]any {
	items := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		item := sanitizeRecord(rec, redactCredential)
		assets, _ := v.Linked(rec.ID, relation)
		item["assets"] = recordList(assets, false)
		items = append(items, item)
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
