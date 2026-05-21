package evidence

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/pridhvi/mnemox/internal/ocr"
	"github.com/pridhvi/mnemox/internal/vault"
)

var (
	ErrNotEvidence          = errors.New("record is not evidence")
	ErrEvidenceBlobMissing  = errors.New("evidence has no blob")
	ErrUnsupportedMediaType = errors.New("ocr extraction is only available for image evidence")
)

func OCRStatus(ctx context.Context) ocr.Status {
	return ocr.TesseractStatus(ctx)
}

func ExtractOCR(ctx context.Context, v *vault.Vault, evidenceID string) (vault.Record, ocr.Result, error) {
	rec, err := v.GetRecord(evidenceID)
	if err != nil {
		return vault.Record{}, ocr.Result{}, err
	}
	if rec.Kind != "evidence" {
		return rec, ocr.Result{}, ErrNotEvidence
	}
	blobID := stringValue(rec.Payload, "blob_id")
	if blobID == "" {
		return rec, ocr.Result{}, ErrEvidenceBlobMissing
	}
	data, err := v.ReadBlob(blobID)
	if err != nil {
		return rec, ocr.Result{}, err
	}
	if !isImage(data) {
		return rec, ocr.Result{}, ErrUnsupportedMediaType
	}
	result, err := ocr.Extract(ctx, data)
	if err != nil && result.Status == "" {
		return rec, result, err
	}
	updated, updateErr := updateOCRMetadata(v, rec, result)
	if updateErr != nil {
		return rec, result, updateErr
	}
	if err != nil {
		return updated, result, err
	}
	return updated, result, nil
}

func updateOCRMetadata(v *vault.Vault, rec vault.Record, result ocr.Result) (vault.Record, error) {
	next := cloneMap(rec.Payload)
	next["ocr_status"] = result.Status
	next["ocr_engine"] = result.Engine
	if result.Text != "" {
		next["ocr_text"] = result.Text
	} else if result.Status == "complete" {
		next["ocr_text"] = ""
	}
	if result.ExtractedAt != "" {
		next["ocr_extracted_at"] = result.ExtractedAt
	}
	if result.Error != "" {
		next["ocr_error"] = result.Error
	} else {
		delete(next, "ocr_error")
	}
	if err := v.UpdateRecord(rec.ID, next); err != nil {
		return rec, err
	}
	return v.GetRecord(rec.ID)
}

func isImage(data []byte) bool {
	return len(data) > 0 && strings.HasPrefix(http.DetectContentType(data), "image/")
}

func cloneMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func stringValue(payload map[string]any, key string) string {
	if value, ok := payload[key].(string); ok {
		return value
	}
	return ""
}

func ErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrUnsupportedMediaType):
		return http.StatusUnsupportedMediaType
	case errors.Is(err, ocr.ErrUnavailable):
		return http.StatusFailedDependency
	case errors.Is(err, ErrNotEvidence):
		return http.StatusBadRequest
	case errors.Is(err, ErrEvidenceBlobMissing):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

func UserMessage(err error) string {
	if errors.Is(err, ocr.ErrUnavailable) {
		return "tesseract is not installed or not available on PATH"
	}
	return fmt.Sprint(err)
}
