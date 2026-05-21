package vault

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	backupMagic       = "mnemox-backup"
	backupVersion     = 1
	backupManifest    = "MANIFEST.sha256"
	backupMaxFileSize = 1 << 40
)

type BackupHeader struct {
	Magic         string       `json:"magic"`
	Version       int          `json:"version"`
	CreatedAt     string       `json:"created_at"`
	Crypto        CryptoConfig `json:"crypto"`
	PayloadSHA256 string       `json:"payload_sha256"`
	PayloadBytes  int          `json:"payload_bytes"`
}

type backupEntry struct {
	Path string
	Data []byte
	Mode int64
}

func (v *Vault) Backup(output string) error {
	if strings.TrimSpace(output) == "" {
		return errors.New("backup output path is required")
	}
	if err := v.checkpoint(); err != nil {
		return err
	}
	config, err := readConfig(v.Root)
	if err != nil {
		return err
	}
	payload, err := v.backupPayload()
	if err != nil {
		return err
	}
	token, err := v.box.encrypt(payload)
	if err != nil {
		return err
	}
	payloadHash := sha256.Sum256(token)
	header := BackupHeader{
		Magic:         backupMagic,
		Version:       backupVersion,
		CreatedAt:     time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
		Crypto:        config.Crypto,
		PayloadSHA256: hex.EncodeToString(payloadHash[:]),
		PayloadBytes:  len(token),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- backup output path is explicitly supplied by the operator.
	if err != nil {
		return err
	}
	if _, err := file.Write(append(headerJSON, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(token); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func RestoreBackup(input, root, passphrase string, force bool) error {
	if strings.TrimSpace(input) == "" {
		return errors.New("backup input path is required")
	}
	if strings.TrimSpace(root) == "" {
		root = DefaultPath()
	}
	if vaultPathExists(root) && !force {
		return fmt.Errorf("vault already exists at %s; use --force to overwrite", root)
	}
	header, token, err := readBackupFile(input)
	if err != nil {
		return err
	}
	box, err := newCipherBox(passphrase, header.Crypto)
	if err != nil {
		return err
	}
	payload, err := box.decrypt(token)
	if err != nil {
		return errors.New("backup restore failed: invalid passphrase or corrupt backup")
	}
	parent := filepath.Dir(root)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	tempRoot, err := os.MkdirTemp(parent, ".mnemox-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempRoot)
	if err := extractBackupPayload(payload, tempRoot); err != nil {
		return err
	}
	if force {
		if err := os.RemoveAll(root); err != nil {
			return err
		}
	}
	if err := os.Rename(tempRoot, root); err != nil {
		return err
	}
	return nil
}

func (v *Vault) checkpoint() error {
	_, err := v.DB.Exec(`PRAGMA wal_checkpoint(FULL)`)
	return err
}

func (v *Vault) backupPayload() ([]byte, error) {
	entries, err := v.collectBackupEntries()
	if err != nil {
		return nil, err
	}
	var manifest bytes.Buffer
	for _, entry := range entries {
		sum := sha256.Sum256(entry.Data)
		fmt.Fprintf(&manifest, "%s  %s\n", hex.EncodeToString(sum[:]), entry.Path)
	}
	entries = append(entries, backupEntry{Path: backupManifest, Data: manifest.Bytes(), Mode: 0o600})

	var payload bytes.Buffer
	gzipWriter := gzip.NewWriter(&payload)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{
			Name: entry.Path,
			Mode: entry.Mode,
			Size: int64(len(entry.Data)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			return nil, err
		}
		if _, err := tarWriter.Write(entry.Data); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			return nil, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}

func (v *Vault) collectBackupEntries() ([]backupEntry, error) {
	paths := []string{"config.json", "vault.db"}
	if _, err := os.Stat(filepath.Join(v.Root, "blobs")); err == nil {
		err = filepath.WalkDir(filepath.Join(v.Root, "blobs"), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(v.Root, path)
			if err != nil {
				return err
			}
			paths = append(paths, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(paths)
	entries := make([]backupEntry, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Join(v.Root, filepath.FromSlash(path))) // #nosec G304 -- paths are collected from the selected vault root.
		if err != nil {
			return nil, err
		}
		entries = append(entries, backupEntry{Path: path, Data: data, Mode: 0o600})
	}
	return entries, nil
}

func readBackupFile(path string) (BackupHeader, []byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- backup path is explicitly supplied by the operator.
	if err != nil {
		return BackupHeader{}, nil, err
	}
	newline := bytes.IndexByte(data, '\n')
	if newline < 0 {
		return BackupHeader{}, nil, errors.New("backup file is missing JSON header")
	}
	var header BackupHeader
	if err := json.Unmarshal(data[:newline], &header); err != nil {
		return BackupHeader{}, nil, err
	}
	if header.Magic != backupMagic || header.Version != backupVersion {
		return BackupHeader{}, nil, fmt.Errorf("unsupported backup format %q version %d", header.Magic, header.Version)
	}
	token := data[newline+1:]
	sum := sha256.Sum256(token)
	if header.PayloadSHA256 != hex.EncodeToString(sum[:]) {
		return BackupHeader{}, nil, errors.New("backup payload checksum mismatch")
	}
	if header.PayloadBytes != 0 && header.PayloadBytes != len(token) {
		return BackupHeader{}, nil, errors.New("backup payload length mismatch")
	}
	return header, token, nil
}

func extractBackupPayload(payload []byte, root string) error {
	gzipReader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	files := map[string][]byte{}
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return fmt.Errorf("unsupported backup tar entry type for %s", header.Name)
		}
		path, err := cleanArchivePath(header.Name)
		if err != nil {
			return err
		}
		if header.Size < 0 || header.Size > backupMaxFileSize {
			return fmt.Errorf("backup entry %s has invalid size", path)
		}
		data, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil {
			return err
		}
		if int64(len(data)) != header.Size {
			return fmt.Errorf("backup entry %s is truncated", path)
		}
		files[path] = data
	}
	if err := verifyManifest(files); err != nil {
		return err
	}
	for path, data := range files {
		if path == backupManifest {
			continue
		}
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			return err
		}
	}
	return os.MkdirAll(filepath.Join(root, "blobs"), 0o700)
}

func verifyManifest(files map[string][]byte) error {
	manifest, ok := files[backupManifest]
	if !ok {
		return errors.New("backup is missing checksum manifest")
	}
	expected := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return fmt.Errorf("invalid manifest line %q", line)
		}
		expected[parts[1]] = parts[0]
	}
	for path, data := range files {
		if path == backupManifest {
			continue
		}
		sum := sha256.Sum256(data)
		if expected[path] != hex.EncodeToString(sum[:]) {
			return fmt.Errorf("backup checksum mismatch for %s", path)
		}
		delete(expected, path)
	}
	if len(expected) != 0 {
		missing := make([]string, 0, len(expected))
		for path := range expected {
			missing = append(missing, path)
		}
		sort.Strings(missing)
		return fmt.Errorf("backup manifest references missing files: %s", strings.Join(missing, ", "))
	}
	return nil
}

func cleanArchivePath(path string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(path))
	if clean == "." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || filepath.IsAbs(clean) {
		return "", fmt.Errorf("invalid backup path %q", path)
	}
	return clean, nil
}

func vaultPathExists(root string) bool {
	if _, err := os.Stat(filepath.Join(root, "config.json")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(root, "vault.db")); err == nil {
		return true
	}
	entries, err := os.ReadDir(root)
	return err == nil && len(entries) > 0
}

func readConfig(root string) (configFile, error) {
	var config configFile
	data, err := os.ReadFile(filepath.Join(root, "config.json")) // #nosec G304 -- root is the user-selected vault directory.
	if err != nil {
		return configFile{}, err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return configFile{}, err
	}
	return config, nil
}
