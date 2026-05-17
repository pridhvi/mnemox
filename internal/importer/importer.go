package importer

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"net/url"
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
	Notes    int `json:"notes"`
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
		findingID, err := v.AddRecord("finding", domain.FindingPayload(domain.Finding{
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
			assetID, err := v.AddRecord("asset", domain.AssetPayload(domain.Asset{Name: target, Type: "url", Value: target, Tags: []string{"import:nuclei"}}))
			if err != nil {
				return result, err
			}
			_ = v.AddLink(findingID, assetID, "affects_asset")
			result.Assets++
		}
	}
	return result, nil
}

func BurpXML(v *vault.Vault, path string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	var parsed burpIssues
	if err := xml.Unmarshal(data, &parsed); err != nil {
		return Result{}, err
	}
	var result Result
	for _, issue := range parsed.Issues {
		target := firstNonEmpty(strings.TrimSpace(issue.Host.Value), strings.TrimSpace(issue.Location))
		if issue.Path != "" && issue.Host.Value != "" {
			target = strings.TrimRight(issue.Host.Value, "/") + issue.Path
		}
		title := firstNonEmpty(strings.TrimSpace(issue.Name), "Burp issue")
		findingID, err := v.AddRecord("finding", domain.FindingPayload(domain.Finding{
			Title:            title,
			Status:           "imported",
			Severity:         normalizeSeverity(issue.Severity),
			AffectedScope:    stringList(target),
			Summary:          strings.TrimSpace(issue.IssueBackground),
			TechnicalDetails: strings.TrimSpace(issue.IssueDetail),
			Impact:           strings.TrimSpace(issue.VulnerabilityClassifications),
			Remediation:      firstNonEmpty(strings.TrimSpace(issue.RemediationDetail), strings.TrimSpace(issue.RemediationBackground)),
			Validation:       strings.TrimSpace("Burp confidence: " + strings.TrimSpace(issue.Confidence)),
			References:       stringList(strings.TrimSpace(issue.References)),
		}))
		if err != nil {
			return result, err
		}
		result.Findings++
		if target != "" {
			assetID, err := v.AddRecord("asset", domain.AssetPayload(domain.Asset{
				Name:  assetNameFromTarget(target),
				Type:  assetTypeFromTarget(target),
				Value: target,
				Tags:  []string{"import:burp"},
				Notes: strings.TrimSpace(issue.Location),
			}))
			if err != nil {
				return result, err
			}
			_ = v.AddLink(findingID, assetID, "affects_asset")
			result.Assets++
		}
	}
	return result, nil
}

func NessusXML(v *vault.Vault, path string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	var parsed nessusData
	if err := xml.Unmarshal(data, &parsed); err != nil {
		return Result{}, err
	}
	var result Result
	for _, report := range parsed.Reports {
		for _, host := range report.Hosts {
			hostName := firstNonEmpty(host.property("host-fqdn"), host.property("host-ip"), host.Name)
			if hostName == "" {
				continue
			}
			assetID, err := v.AddRecord("asset", domain.AssetPayload(domain.Asset{
				Name:  hostName,
				Type:  "host",
				Value: firstNonEmpty(host.property("host-ip"), hostName),
				Tags:  []string{"import:nessus"},
				Notes: "Nessus host: " + host.Name,
			}))
			if err != nil {
				return result, err
			}
			result.Assets++
			for _, item := range host.Items {
				title := firstNonEmpty(item.PluginName, "Nessus plugin "+item.PluginID)
				scope := hostName
				if item.Port != "" && item.Port != "0" {
					scope = fmt.Sprintf("%s:%s/%s", hostName, item.Port, item.Protocol)
				}
				findingID, err := v.AddRecord("finding", domain.FindingPayload(domain.Finding{
					Title:            title,
					Status:           "imported",
					Severity:         nessusSeverity(item),
					AffectedScope:    []string{scope},
					Summary:          firstNonEmpty(item.Synopsis, item.Description),
					TechnicalDetails: strings.TrimSpace(item.PluginOutput),
					Impact:           strings.TrimSpace(item.Description),
					Remediation:      strings.TrimSpace(item.Solution),
					References:       compactStrings([]string{item.SeeAlso, item.CVE, item.BID, item.Xref}),
				}))
				if err != nil {
					return result, err
				}
				_ = v.AddLink(findingID, assetID, "affects_asset")
				result.Findings++
			}
		}
	}
	return result, nil
}

func BloodHoundJSON(v *vault.Vault, path string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return Result{}, err
	}
	nodes, edges := bloodHoundGraph(raw)
	var result Result
	assetIDs := map[string]string{}
	assetNames := map[string]string{}
	for _, node := range nodes {
		name := firstNonEmpty(node.Name, node.ID)
		if name == "" {
			continue
		}
		if assetIDs[name] != "" {
			if node.ID != "" {
				assetIDs[node.ID] = assetIDs[name]
				assetNames[node.ID] = name
			}
			continue
		}
		assetID, err := v.AddRecord("asset", domain.AssetPayload(domain.Asset{
			Name:  name,
			Type:  bloodHoundAssetType(node.Kind),
			Value: name,
			Tags:  []string{"import:bloodhound"},
			Notes: firstNonEmpty(node.Kind, "BloodHound node"),
		}))
		if err != nil {
			return result, err
		}
		result.Assets++
		if node.ID != "" {
			assetIDs[node.ID] = assetID
			assetNames[node.ID] = name
		}
		assetIDs[name] = assetID
		assetNames[name] = name
	}
	ensureAsset := func(name string) (string, error) {
		name = strings.TrimSpace(name)
		if name == "" {
			return "", nil
		}
		if assetID := assetIDs[name]; assetID != "" {
			return assetID, nil
		}
		assetID, err := v.AddRecord("asset", domain.AssetPayload(domain.Asset{
			Name:  name,
			Type:  "other",
			Value: name,
			Tags:  []string{"import:bloodhound"},
			Notes: "BloodHound path endpoint",
		}))
		if err != nil {
			return "", err
		}
		assetIDs[name] = assetID
		assetNames[name] = name
		result.Assets++
		return assetID, nil
	}
	for _, edge := range edges {
		source := firstNonEmpty(edge.Source, edge.Start, edge.From)
		target := firstNonEmpty(edge.Target, edge.End, edge.To)
		relation := firstNonEmpty(edge.Relationship, edge.Label, edge.Kind, "related_to")
		sourceName := firstNonEmpty(assetNames[source], source)
		targetName := firstNonEmpty(assetNames[target], target)
		text := strings.TrimSpace(fmt.Sprintf("%s --[%s]--> %s", sourceName, relation, targetName))
		if text == "--[related_to]-->" {
			continue
		}
		noteID, err := v.AddRecord("note", domain.NotePayload(domain.Note{
			Text: text,
			Tags: []string{"import:bloodhound", relation},
		}))
		if err != nil {
			return result, err
		}
		result.Notes++
		sourceID, err := ensureAsset(source)
		if err != nil {
			return result, err
		}
		targetID, err := ensureAsset(target)
		if err != nil {
			return result, err
		}
		if assetID := sourceID; assetID != "" {
			_ = v.AddLink(noteID, assetID, "note_asset")
		}
		if assetID := targetID; assetID != "" {
			_ = v.AddLink(noteID, assetID, "note_asset")
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

type burpIssues struct {
	Issues []struct {
		Name string `xml:"name"`
		Host struct {
			Value string `xml:",chardata"`
		} `xml:"host"`
		Path                         string `xml:"path"`
		Location                     string `xml:"location"`
		Severity                     string `xml:"severity"`
		Confidence                   string `xml:"confidence"`
		IssueBackground              string `xml:"issueBackground"`
		IssueDetail                  string `xml:"issueDetail"`
		RemediationBackground        string `xml:"remediationBackground"`
		RemediationDetail            string `xml:"remediationDetail"`
		References                   string `xml:"references"`
		VulnerabilityClassifications string `xml:"vulnerabilityClassifications"`
	} `xml:"issue"`
}

type nessusData struct {
	Reports []struct {
		Hosts []nessusHost `xml:"ReportHost"`
	} `xml:"Report"`
}

type nessusHost struct {
	Name       string `xml:"name,attr"`
	Properties []struct {
		Name  string `xml:"name,attr"`
		Value string `xml:",chardata"`
	} `xml:"HostProperties>tag"`
	Items []nessusItem `xml:"ReportItem"`
}

type nessusItem struct {
	PluginID     string `xml:"pluginID,attr"`
	PluginName   string `xml:"pluginName,attr"`
	Port         string `xml:"port,attr"`
	Protocol     string `xml:"protocol,attr"`
	Severity     string `xml:"severity,attr"`
	RiskFactor   string `xml:"risk_factor"`
	Synopsis     string `xml:"synopsis"`
	Description  string `xml:"description"`
	Solution     string `xml:"solution"`
	PluginOutput string `xml:"plugin_output"`
	SeeAlso      string `xml:"see_also"`
	CVE          string `xml:"cve"`
	BID          string `xml:"bid"`
	Xref         string `xml:"xref"`
}

func (h nessusHost) property(name string) string {
	for _, property := range h.Properties {
		if property.Name == name {
			return strings.TrimSpace(property.Value)
		}
	}
	return ""
}

type bloodHoundNode struct {
	ID   string
	Name string
	Kind string
}

type bloodHoundEdge struct {
	Source       string
	Target       string
	Start        string
	End          string
	From         string
	To           string
	Relationship string
	Label        string
	Kind         string
}

func bloodHoundGraph(raw any) ([]bloodHoundNode, []bloodHoundEdge) {
	var nodes []bloodHoundNode
	var edges []bloodHoundEdge
	collectBloodHound(raw, &nodes, &edges)
	return nodes, edges
}

func collectBloodHound(value any, nodes *[]bloodHoundNode, edges *[]bloodHoundEdge) {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			collectBloodHound(item, nodes, edges)
		}
	case map[string]any:
		if rawNodes, ok := firstValue(typed, "nodes", "Nodes").([]any); ok {
			for _, item := range rawNodes {
				if node, ok := parseBloodHoundNode(item); ok {
					*nodes = append(*nodes, node)
				}
			}
		}
		if rawEdges, ok := firstValue(typed, "edges", "Edges", "relationships", "Relationships", "links").([]any); ok {
			for _, item := range rawEdges {
				if edge, ok := parseBloodHoundEdge(item); ok {
					*edges = append(*edges, edge)
				}
			}
		}
		if rawData, ok := typed["data"]; ok {
			collectBloodHound(rawData, nodes, edges)
		}
		if node, ok := parseBloodHoundNode(typed); ok {
			*nodes = append(*nodes, node)
		}
		if edge, ok := parseBloodHoundEdge(typed); ok {
			*edges = append(*edges, edge)
		}
	}
}

func parseBloodHoundNode(value any) (bloodHoundNode, bool) {
	object, ok := value.(map[string]any)
	if !ok {
		return bloodHoundNode{}, false
	}
	properties, _ := firstValue(object, "properties", "Properties", "props").(map[string]any)
	id := firstNonEmpty(
		anyString(firstValue(object, "id", "objectid", "ObjectIdentifier", "ObjectID")),
		anyString(firstValue(properties, "objectid", "ObjectIdentifier", "ObjectID", "sid")),
	)
	name := firstNonEmpty(
		anyString(firstValue(object, "name", "label", "displayName")),
		anyString(firstValue(properties, "name", "displayname", "samaccountname", "principalname")),
		id,
	)
	kind := firstNonEmpty(
		anyString(firstValue(object, "kind", "type", "category", "labels")),
		anyString(firstValue(properties, "type", "kind")),
	)
	if name == "" || looksLikeEdge(object) {
		return bloodHoundNode{}, false
	}
	return bloodHoundNode{ID: id, Name: name, Kind: kind}, true
}

func parseBloodHoundEdge(value any) (bloodHoundEdge, bool) {
	object, ok := value.(map[string]any)
	if !ok {
		return bloodHoundEdge{}, false
	}
	properties, _ := firstValue(object, "properties", "Properties", "props").(map[string]any)
	edge := bloodHoundEdge{
		Source:       firstNonEmpty(anyString(firstValue(object, "source", "sourceId", "source_id", "startNode", "start")), anyString(firstValue(properties, "source", "sourceid", "start"))),
		Target:       firstNonEmpty(anyString(firstValue(object, "target", "targetId", "target_id", "endNode", "end")), anyString(firstValue(properties, "target", "targetid", "end"))),
		From:         anyString(firstValue(object, "from")),
		To:           anyString(firstValue(object, "to")),
		Start:        anyString(firstValue(object, "start")),
		End:          anyString(firstValue(object, "end")),
		Relationship: firstNonEmpty(anyString(firstValue(object, "relationship", "relationshipType", "edge_type", "kind")), anyString(firstValue(properties, "relationship", "relationshiptype", "kind"))),
		Label:        anyString(firstValue(object, "label")),
		Kind:         anyString(firstValue(object, "type")),
	}
	if firstNonEmpty(edge.Source, edge.Start, edge.From) == "" || firstNonEmpty(edge.Target, edge.End, edge.To) == "" {
		return bloodHoundEdge{}, false
	}
	return edge, true
}

func looksLikeEdge(object map[string]any) bool {
	return firstNonEmpty(
		anyString(firstValue(object, "source", "sourceId", "source_id", "startNode", "from")),
		anyString(firstValue(object, "target", "targetId", "target_id", "endNode", "to")),
	) != ""
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

func firstValue(item map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := item[key]; ok {
			return value
		}
		lower := strings.ToLower(key)
		for actual, value := range item {
			if strings.ToLower(actual) == lower {
				return value
			}
		}
	}
	return nil
}

func anyString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case []any:
		var parts []string
		for _, item := range typed {
			if part := anyString(item); part != "" {
				parts = append(parts, part)
			}
		}
		return strings.Join(parts, ",")
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func stringList(values ...string) []string {
	var out []string
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func compactStrings(values []string) []string {
	return stringList(values...)
}

func normalizeSeverity(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "INFO", "INFORMATIONAL", "NONE":
		return "INFO"
	default:
		return "Unscored"
	}
}

func nessusSeverity(item nessusItem) string {
	if severity := normalizeSeverity(item.RiskFactor); severity != "Unscored" {
		return severity
	}
	switch strings.TrimSpace(item.Severity) {
	case "4":
		return "CRITICAL"
	case "3":
		return "HIGH"
	case "2":
		return "MEDIUM"
	case "1":
		return "LOW"
	case "0":
		return "INFO"
	default:
		return "Unscored"
	}
}

func assetNameFromTarget(target string) string {
	parsed, err := url.Parse(target)
	if err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return target
}

func assetTypeFromTarget(target string) string {
	parsed, err := url.Parse(target)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return "url"
	}
	return "host"
}

func bloodHoundAssetType(kind string) string {
	kind = strings.ToLower(kind)
	switch {
	case strings.Contains(kind, "computer"):
		return "host"
	case strings.Contains(kind, "user"):
		return "user"
	case strings.Contains(kind, "group"):
		return "group"
	case strings.Contains(kind, "domain"):
		return "domain"
	default:
		return "other"
	}
}

func isImage(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png", ".jpg", ".jpeg", ".webp":
		return true
	default:
		return false
	}
}
