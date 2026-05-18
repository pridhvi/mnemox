package ocr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const Engine = "tesseract"

var (
	ErrUnavailable = errors.New("tesseract is not available")
	ErrFailed      = errors.New("ocr extraction failed")
)

type Status struct {
	Available bool   `json:"available"`
	Engine    string `json:"engine"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Result struct {
	Text        string `json:"text"`
	Status      string `json:"status"`
	Engine      string `json:"engine"`
	Version     string `json:"version,omitempty"`
	ExtractedAt string `json:"extracted_at,omitempty"`
	Error       string `json:"error,omitempty"`
}

func TesseractStatus(ctx context.Context) Status {
	path, err := exec.LookPath(Engine)
	if err != nil {
		return Status{Available: false, Engine: Engine, Error: "install tesseract to enable local OCR"}
	}
	return Status{Available: true, Engine: Engine, Version: tesseractVersion(ctx, path)}
}

func Extract(ctx context.Context, image []byte) (Result, error) {
	status := TesseractStatus(ctx)
	if !status.Available {
		return Result{
			Status: "unavailable",
			Engine: Engine,
			Error:  status.Error,
		}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	temp, err := os.CreateTemp("", "mnemox-ocr-*")
	if err != nil {
		return Result{}, err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if _, err := temp.Write(image); err != nil {
		_ = temp.Close()
		return Result{}, err
	}
	if err := temp.Close(); err != nil {
		return Result{}, err
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, Engine, tempName, "stdout")
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			message = "tesseract timed out"
		}
		return Result{
			Status:      "failed",
			Engine:      Engine,
			Version:     status.Version,
			ExtractedAt: utcNow(),
			Error:       truncate(message, 240),
		}, fmt.Errorf("%w: %s", ErrFailed, message)
	}
	return Result{
		Text:        strings.TrimSpace(string(output)),
		Status:      "complete",
		Engine:      Engine,
		Version:     status.Version,
		ExtractedAt: utcNow(),
	}, nil
}

func tesseractVersion(ctx context.Context, path string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
	return line
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return strings.TrimSpace(value[:limit]) + "..."
}

func utcNow() string {
	return time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
}
