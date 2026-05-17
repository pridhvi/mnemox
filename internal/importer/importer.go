package importer

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"mnemox/internal/domain"
	"mnemox/internal/vault"
)

type Result struct {
	Assets   int `json:"assets"`
	Findings int `json:"findings"`
	Evidence int `json:"evidence"`
}

func NmapXML(v *vault.Vault, path string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	var parsed nmapRun
	if err := xml.Unmarshal(data, &parsed); err != nil {
		return Result{}, err
	}
	var result Result
	for _, host := range parsed.Hosts {
		name := host.Address.Addr
		for _, hostname := range host.Hostnames.Names {
			if hostname.Name != "" {
				name = hostname.Name
				break
			}
		}
		if name == "" {
			continue
		}
		openPorts := []string{}
		for _, port := range host.Ports.Ports {
			if port.State.State == "open" {
				label := fmt.Sprintf("%d/%s", port.PortID, port.Protocol)
				if port.Service.Name != "" {
					label += " " + port.Service.Name
				}
				openPorts = append(openPorts, label)
			}
		}
		_, err := v.AddRecord("asset", domain.AssetPayload(domain.Asset{
			Name:  name,
			Type:  "host",
			Value: host.Address.Addr,
			Tags:  []string{"import:nmap"},
			Notes: "Open services: " + strings.Join(openPorts, ", "),
		}))
		if err != nil {
			return result, err
		}
		result.Assets++
	}
	return result, nil
}

func NucleiJSON(v *vault.Vault, path string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	var result Result
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var item map[string]any
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			return result, err
		}
		title := stringValue(item, "info.name")
		if title == "" {
			title = stringValue(item, "template-id")
		}
		if title == "" {
			title = "nuclei finding"
		}
		target := stringValue(item, "host")
		if target == "" {
			target = stringValue(item, "matched-at")
		}
		severity := strings.ToUpper(stringValue(item, "info.severity"))
		if severity == "" {
			severity = "Unscored"
		}
		_, err := v.AddRecord("finding", domain.FindingPayload(domain.Finding{
			Title:         title,
			Status:        "imported",
			Severity:      severity,
			AffectedScope: []string{target},
			Summary:       stringValue(item, "matcher-name"),
			References:    []string{stringValue(item, "template-url")},
		}))
		if err != nil {
			return result, err
		}
		result.Findings++
		if target != "" {
			_, _ = v.AddRecord("asset", domain.AssetPayload(domain.Asset{Name: target, Type: "url", Value: target, Tags: []string{"import:nuclei"}}))
			result.Assets++
		}
	}
	return result, nil
}

func ScreenshotFolder(v *vault.Vault, folder string) (Result, error) {
	var result Result
	err := filepath.WalkDir(folder, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isImage(path) {
			return nil
		}
		blobID, err := v.StoreBlob(path)
		if err != nil {
			return err
		}
		_, err = v.AddRecord("evidence", domain.EvidencePayload(domain.Evidence{
			Kind:         "screenshot",
			Caption:      strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
			OriginalPath: path,
			BlobID:       blobID,
			Tags:         []string{"import:screenshot"},
		}))
		if err == nil {
			result.Evidence++
		}
		return err
	})
	return result, err
}

type nmapRun struct {
	Hosts []struct {
		Address struct {
			Addr string `xml:"addr,attr"`
		} `xml:"address"`
		Hostnames struct {
			Names []struct {
				Name string `xml:"name,attr"`
			} `xml:"hostname"`
		} `xml:"hostnames"`
		Ports struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   int    `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name string `xml:"name,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

func stringValue(item map[string]any, path string) string {
	var current any = item
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = object[part]
	}
	if current == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(current))
}

func isImage(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png", ".jpg", ".jpeg", ".webp":
		return true
	default:
		return false
	}
}
