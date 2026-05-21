package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pridhvi/mnemox/internal/console"
	"github.com/pridhvi/mnemox/internal/cvss"
	"github.com/pridhvi/mnemox/internal/domain"
	evidencepkg "github.com/pridhvi/mnemox/internal/evidence"
	"github.com/pridhvi/mnemox/internal/importer"
	"github.com/pridhvi/mnemox/internal/packet"
	"github.com/pridhvi/mnemox/internal/vault"
	"github.com/pridhvi/mnemox/internal/web"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type App struct {
	root            *cobra.Command
	vaultPath       string
	passphraseStdin bool
	passphraseFile  string
}

func New() *App {
	a := &App{}
	root := &cobra.Command{
		Use:           "mnemox",
		Short:         "Local-first pentest engagement memory.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return console.Run(a.ExecuteLine, a.vaultPath)
		},
	}
	root.PersistentFlags().StringVar(&a.vaultPath, "vault", "", "path to vault directory, default .mnemox or MNEMOX_VAULT")
	root.PersistentFlags().BoolVar(&a.passphraseStdin, "passphrase-stdin", false, "read the vault passphrase from stdin")
	root.PersistentFlags().StringVar(&a.passphraseFile, "passphrase-file", "", "read the vault passphrase from a file")
	root.AddCommand(a.initCmd(), a.findingCmd(), a.assetCmd(), a.noteCmd(), a.evidenceCmd(), a.credCmd(), a.importCmd(), a.askCmd(), a.cvssCmd(), a.packetCmd(), a.exportBlobCmd(), a.backupCmd(), a.vaultCmd(), a.serveCmd())
	a.root = root
	return a
}

func (a *App) Execute() error {
	if err := a.root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "mnemox: error:", err)
		return err
	}
	return nil
}

func (a *App) ExecuteLine(args []string) error {
	if len(args) == 0 {
		return nil
	}
	if args[0] == "use" {
		if len(args) != 2 {
			return fmt.Errorf("usage: use <vault-path>")
		}
		a.vaultPath = args[1]
		fmt.Println("Vault path:", a.resolvedVaultPath())
		return nil
	}
	cmd := a.root
	cmd.SetArgs(args)
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)
	return cmd.Execute()
}

func (a *App) resolvedVaultPath() string {
	if a.vaultPath != "" {
		abs, _ := filepath.Abs(a.vaultPath)
		return abs
	}
	return vault.DefaultPath()
}

func (a *App) openVault() (*vault.Vault, error) {
	if err := a.configurePassphraseSource(); err != nil {
		return nil, err
	}
	return vault.Open(a.resolvedVaultPath())
}

func (a *App) configurePassphraseSource() error {
	return vault.ConfigurePassphraseSource(vault.PassphraseOptions{
		FromStdin: a.passphraseStdin,
		File:      a.passphraseFile,
	})
}

func (a *App) initCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create an encrypted vault.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.configurePassphraseSource(); err != nil {
				return err
			}
			v, err := vault.Create(a.resolvedVaultPath(), name)
			if err != nil {
				return err
			}
			defer v.Close()
			fmt.Println("Initialized Mnemox vault at", a.resolvedVaultPath())
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "Pentest Engagement", "engagement name")
	return cmd
}

func (a *App) findingCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "finding", Short: "Manage findings."}
	var severity, status, summary, technical, impact, remediation, validation string
	var scope, refs []string
	add := &cobra.Command{
		Use:   "add <title>",
		Short: "Add a finding.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			id, err := v.AddRecord("finding", map[string]any{
				"title":             args[0],
				"status":            status,
				"severity":          severity,
				"affected_scope":    stringSlice(scope),
				"summary":           summary,
				"technical_details": technical,
				"impact":            impact,
				"remediation":       remediation,
				"validation":        validation,
				"references":        stringSlice(refs),
				"open_questions":    []string{},
			})
			if err != nil {
				return err
			}
			fmt.Printf("Added finding %s: %s\n", id, args[0])
			return nil
		},
	}
	add.Flags().StringVar(&severity, "severity", "Unscored", "finding severity")
	add.Flags().StringVar(&status, "status", "draft", "finding status")
	add.Flags().StringVar(&summary, "summary", "", "report-ready summary")
	add.Flags().StringVar(&technical, "technical-details", "", "technical details")
	add.Flags().StringVar(&impact, "impact", "", "impact statement")
	add.Flags().StringVar(&remediation, "remediation", "", "remediation guidance")
	add.Flags().StringVar(&validation, "validation", "", "fix validation guidance")
	add.Flags().StringArrayVar(&scope, "affected-scope", nil, "affected asset/scope item")
	add.Flags().StringArrayVar(&refs, "reference", nil, "reference URL or identifier")
	cmd.AddCommand(add)
	return cmd
}

func (a *App) assetCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "asset", Short: "Manage assets."}
	var assetType, value, notes string
	var tags []string
	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Add an asset.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			if value == "" {
				value = args[0]
			}
			id, err := v.AddRecord("asset", domain.AssetPayload(domain.Asset{
				Name:  args[0],
				Type:  assetType,
				Value: value,
				Tags:  tags,
				Notes: notes,
			}))
			if err != nil {
				return err
			}
			fmt.Printf("Added asset %s: %s\n", id, args[0])
			return nil
		},
	}
	add.Flags().StringVar(&assetType, "type", "host", "asset type")
	add.Flags().StringVar(&value, "value", "", "asset value")
	add.Flags().StringVar(&notes, "notes", "", "asset notes")
	add.Flags().StringArrayVar(&tags, "tag", nil, "tag")
	list := &cobra.Command{
		Use:   "list",
		Short: "List assets.",
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			records, err := v.Records("asset")
			if err != nil {
				return err
			}
			for _, rec := range records {
				fmt.Printf("[%s] %s (%s) %s\n", shortID(rec.ID), rec.Payload["name"], rec.Payload["type"], rec.Payload["value"])
			}
			return nil
		},
	}
	cmd.AddCommand(add, list)
	return cmd
}

func (a *App) noteCmd() *cobra.Command {
	var finding, asset string
	var tags []string
	cmd := &cobra.Command{
		Use:   "note <text>",
		Short: "Add an operator note.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			id, err := v.AddRecord("note", map[string]any{"text": args[0], "asset": asset, "tags": stringSlice(tags)})
			if err != nil {
				return err
			}
			if finding != "" {
				rec, err := v.FindOne("finding", finding)
				if err != nil {
					return err
				}
				if err := v.AddLink(rec.ID, id, "has_note"); err != nil {
					return err
				}
			}
			fmt.Println("Added note", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&finding, "finding", "", "finding title or ID")
	cmd.Flags().StringVar(&asset, "asset", "", "related asset")
	cmd.Flags().StringArrayVar(&tags, "tag", nil, "tag")
	return cmd
}

func (a *App) evidenceCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "evidence", Short: "Manage evidence."}
	var finding, kind, caption string
	var tags []string
	add := &cobra.Command{
		Use:   "add <path>",
		Short: "Encrypt and attach an evidence file.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			blobID, err := v.StoreBlob(args[0])
			if err != nil {
				return err
			}
			id, err := v.AddRecord("evidence", map[string]any{
				"kind":          kind,
				"caption":       caption,
				"original_path": args[0],
				"blob_id":       blobID,
				"tags":          stringSlice(tags),
			})
			if err != nil {
				return err
			}
			if finding != "" {
				rec, err := v.FindOne("finding", finding)
				if err != nil {
					return err
				}
				if err := v.AddLink(rec.ID, id, "has_evidence"); err != nil {
					return err
				}
			}
			fmt.Printf("Added evidence %s with blob %s\n", id, blobID)
			return nil
		},
	}
	add.Flags().StringVar(&finding, "finding", "", "finding title or ID")
	add.Flags().StringVar(&kind, "kind", "file", "evidence kind")
	add.Flags().StringVar(&caption, "caption", "", "evidence caption")
	add.Flags().StringArrayVar(&tags, "tag", nil, "tag")
	ocrCmd := &cobra.Command{
		Use:   "ocr <evidence-id>",
		Short: "Extract local OCR text from screenshot evidence.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			rec, result, err := evidencepkg.ExtractOCR(context.Background(), v, args[0])
			if err != nil {
				return fmt.Errorf("%s", evidencepkg.UserMessage(err))
			}
			fmt.Printf("Extracted OCR for evidence %s: %d characters\n", rec.ID, len(result.Text))
			return nil
		},
	}
	cmd.AddCommand(add, ocrCmd)
	return cmd
}

func (a *App) credCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cred", Short: "Manage credentials."}
	var username, secret, scope string
	var tags []string
	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Add an encrypted credential.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if secret == "" {
				fmt.Print("Credential secret: ")
				value, err := console.ReadSecret()
				if err != nil {
					return err
				}
				secret = value
			}
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			id, err := v.AddRecord("credential", map[string]any{
				"name":     args[0],
				"username": username,
				"secret":   secret,
				"scope":    scope,
				"tags":     stringSlice(tags),
			})
			if err != nil {
				return err
			}
			fmt.Printf("Added credential %s: %s\n", id, args[0])
			return nil
		},
	}
	add.Flags().StringVar(&username, "username", "", "credential username")
	add.Flags().StringVar(&secret, "secret", "", "credential secret")
	add.Flags().StringVar(&scope, "scope", "", "credential scope")
	add.Flags().StringArrayVar(&tags, "tag", nil, "tag")
	cmd.AddCommand(add)
	return cmd
}

func (a *App) importCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "import", Short: "Import tool output."}
	nmap := &cobra.Command{
		Use:   "nmap <xml-path>",
		Short: "Import Nmap XML hosts and services as assets.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			result, err := importer.NmapXML(v, args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Imported %d assets\n", result.Assets)
			return nil
		},
	}
	nuclei := &cobra.Command{
		Use:   "nuclei <jsonl-path>",
		Short: "Import nuclei JSONL findings and assets.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			result, err := importer.NucleiJSON(v, args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Imported %d findings and %d assets\n", result.Findings, result.Assets)
			return nil
		},
	}
	burp := &cobra.Command{
		Use:   "burp <xml-path>",
		Short: "Import Burp Suite XML issues as findings and assets.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			result, err := importer.BurpXML(v, args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Imported %d findings and %d assets\n", result.Findings, result.Assets)
			return nil
		},
	}
	nessus := &cobra.Command{
		Use:   "nessus <nessus-path>",
		Short: "Import Nessus XML report items as findings and assets.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			result, err := importer.NessusXML(v, args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Imported %d findings and %d assets\n", result.Findings, result.Assets)
			return nil
		},
	}
	bloodhound := &cobra.Command{
		Use:   "bloodhound <json-path>",
		Short: "Import BloodHound JSON graph/path exports as assets and relationship notes.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			result, err := importer.BloodHoundJSON(v, args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Imported %d assets and %d relationship notes\n", result.Assets, result.Notes)
			return nil
		},
	}
	screenshots := &cobra.Command{
		Use:   "screenshots <folder>",
		Short: "Import a folder of screenshots as evidence.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			result, err := importer.ScreenshotFolder(v, args[0])
			if err != nil {
				return err
			}
			fmt.Printf("Imported %d evidence items\n", result.Evidence)
			return nil
		},
	}
	cmd.AddCommand(nmap, nuclei, burp, nessus, bloodhound, screenshots)
	return cmd
}

func (a *App) askCmd() *cobra.Command {
	var limit int
	var semantic bool
	cmd := &cobra.Command{
		Use:   "ask <query>",
		Short: "Search decrypted local memory.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			var hits []vault.SearchHit
			if semantic {
				hits, err = v.SemanticSearch(args[0], "", limit)
			} else {
				hits, err = v.Search(args[0], limit)
			}
			if err != nil {
				return err
			}
			if len(hits) == 0 {
				fmt.Println("No matching memory found.")
				return nil
			}
			for _, hit := range hits {
				fmt.Printf("[%s:%s] %s (score %d)\n  %s\n", hit.Kind, shortID(hit.ID), hit.Title, hit.Score, hit.Excerpt)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 10, "maximum search results")
	cmd.Flags().BoolVar(&semantic, "semantic", false, "use local semantic search with the encrypted vault cache")
	return cmd
}

func (a *App) cvssCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cvss", Short: "CVSS v4.0 tools."}
	var vector, notes string
	var av, ac, at, pr, ui, vc, vi, va, sc, si, sa string
	score := &cobra.Command{
		Use:   "score <finding>",
		Short: "Calculate and store a CVSS v4.0 Base score.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var result cvss.Result
			var err error
			if vector != "" {
				result, err = cvss.FromVector(vector)
			} else {
				result, err = cvss.FromMetrics(map[string]string{
					"AV": av, "AC": ac, "AT": at, "PR": pr, "UI": ui,
					"VC": vc, "VI": vi, "VA": va, "SC": sc, "SI": si, "SA": sa,
				})
			}
			if err != nil {
				return err
			}
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			rec, err := v.FindOne("finding", args[0])
			if err != nil {
				return err
			}
			rec.Payload["cvss"] = map[string]any{
				"vector":   result.Vector,
				"score":    result.Score,
				"severity": result.Severity,
				"metrics":  result.Metrics,
				"notes":    notes,
			}
			if value, _ := rec.Payload["severity"].(string); value == "" || value == "Unscored" {
				rec.Payload["severity"] = result.Severity
			}
			if err := v.UpdateRecord(rec.ID, rec.Payload); err != nil {
				return err
			}
			fmt.Println(result.Vector)
			fmt.Printf("Score: %.1f (%s)\n", result.Score, result.Severity)
			return nil
		},
	}
	score.Flags().StringVar(&vector, "vector", "", "CVSS v4.0 vector")
	score.Flags().StringVar(&notes, "notes", "", "CVSS scoring rationale")
	score.Flags().StringVar(&av, "av", "", cvss.MetricNames["AV"])
	score.Flags().StringVar(&ac, "ac", "", cvss.MetricNames["AC"])
	score.Flags().StringVar(&at, "at", "", cvss.MetricNames["AT"])
	score.Flags().StringVar(&pr, "pr", "", cvss.MetricNames["PR"])
	score.Flags().StringVar(&ui, "ui", "", cvss.MetricNames["UI"])
	score.Flags().StringVar(&vc, "vc", "", cvss.MetricNames["VC"])
	score.Flags().StringVar(&vi, "vi", "", cvss.MetricNames["VI"])
	score.Flags().StringVar(&va, "va", "", cvss.MetricNames["VA"])
	score.Flags().StringVar(&sc, "sc", "", cvss.MetricNames["SC"])
	score.Flags().StringVar(&si, "si", "", cvss.MetricNames["SI"])
	score.Flags().StringVar(&sa, "sa", "", cvss.MetricNames["SA"])
	cmd.AddCommand(score)
	return cmd
}

func (a *App) packetCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "packet", Short: "Build report-ready finding packets."}
	var output string
	var bundleOutput, bundleAsset string
	build := &cobra.Command{
		Use:   "build <finding>",
		Short: "Render a Markdown Finding Packet.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			rec, err := v.FindOne("finding", args[0])
			if err != nil {
				return err
			}
			markdown, err := packet.Render(v, rec.ID)
			if err != nil {
				return err
			}
			if output != "" {
				if err := os.WriteFile(output, []byte(markdown), 0o600); err != nil {
					return err
				}
				fmt.Println("Wrote", output)
				return nil
			}
			fmt.Print(markdown)
			return nil
		},
	}
	build.Flags().StringVar(&output, "output", "", "write Markdown to file")
	bundle := &cobra.Command{
		Use:   "bundle <finding>",
		Short: "Render a cited evidence bundle for prompt-ready report drafting.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			rec, err := v.FindOne("finding", args[0])
			if err != nil {
				return err
			}
			var assetID string
			if bundleAsset != "" {
				asset, err := v.FindOne("asset", bundleAsset)
				if err != nil {
					return err
				}
				assetID = asset.ID
			}
			markdown, err := packet.RenderCitationBundle(v, rec.ID, packet.CitationBundleOptions{AssetID: assetID})
			if err != nil {
				return err
			}
			if bundleOutput != "" {
				if err := os.WriteFile(bundleOutput, []byte(markdown), 0o600); err != nil {
					return err
				}
				fmt.Println("Wrote", bundleOutput)
				return nil
			}
			fmt.Print(markdown)
			return nil
		},
	}
	bundle.Flags().StringVar(&bundleAsset, "asset", "", "limit bundle to evidence and notes linked to an asset")
	bundle.Flags().StringVar(&bundleOutput, "output", "", "write Markdown to file")
	cmd.AddCommand(build, bundle)
	return cmd
}

func (a *App) exportBlobCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export-blob <blob-id> <output>",
		Short: "Decrypt an evidence blob to a file.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			if err := v.ExportBlob(args[0], args[1]); err != nil {
				return err
			}
			fmt.Printf("Exported blob %s to %s\n", args[0], args[1])
			return nil
		},
	}
	return cmd
}

func (a *App) backupCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "backup", Short: "Create and restore encrypted vault backups."}
	create := &cobra.Command{
		Use:   "create <file.mnemoxbak>",
		Short: "Create an encrypted full-vault backup.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			if err := v.Backup(args[0]); err != nil {
				return err
			}
			fmt.Println("Wrote encrypted backup", args[0])
			return nil
		},
	}
	var force bool
	restore := &cobra.Command{
		Use:   "restore <file.mnemoxbak>",
		Short: "Restore an encrypted full-vault backup.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.configurePassphraseSource(); err != nil {
				return err
			}
			passphrase, err := vault.ReadPassphrase(false)
			if err != nil {
				return err
			}
			if err := vault.RestoreBackup(args[0], a.resolvedVaultPath(), passphrase, force); err != nil {
				return err
			}
			fmt.Println("Restored encrypted backup to", a.resolvedVaultPath())
			return nil
		},
	}
	restore.Flags().BoolVar(&force, "force", false, "overwrite an existing vault path")
	cmd.AddCommand(create, restore)
	return cmd
}

func (a *App) vaultCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "vault", Short: "Manage vault maintenance tasks."}
	var backupPath string
	migrate := &cobra.Command{
		Use:   "migrate-v2",
		Short: "Create an encrypted backup and build the v2 query index.",
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault()
			if err != nil {
				return err
			}
			defer v.Close()
			writtenBackup, err := v.MigrateV2(backupPath)
			if err != nil {
				return err
			}
			fmt.Println("Vault v2 query index ready")
			if writtenBackup != "" {
				fmt.Println("Encrypted migration backup:", writtenBackup)
			}
			return nil
		},
	}
	migrate.Flags().StringVar(&backupPath, "backup", "", "encrypted backup path to create before migration")
	cmd.AddCommand(migrate)
	return cmd
}

func (a *App) serveCmd() *cobra.Command {
	var addr string
	var port int
	var allowRemote bool
	var lockAfter time.Duration
	var basicAuthUser string
	var basicAuthPasswordFile string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the local Mnemox web UI.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if addr == "" {
				addr = "127.0.0.1"
			}
			if !allowRemote && addr != "127.0.0.1" && addr != "localhost" && addr != "::1" {
				return fmt.Errorf("refusing to bind non-local address %s without --allow-remote", addr)
			}
			basicAuth, err := basicAuthConfig(allowRemote || cmd.Flags().Changed("basic-auth-user") || basicAuthPasswordFile != "", basicAuthUser, basicAuthPasswordFile)
			if err != nil {
				return err
			}
			bind := addr + ":" + strconv.Itoa(port)
			server := web.New(web.Options{VaultPath: a.resolvedVaultPath(), Addr: bind, LockAfter: lockAfter, BasicAuth: basicAuth})
			listener, err := server.Listen()
			if err != nil {
				return err
			}
			fmt.Println("Mnemox web UI:", server.URL(listener))
			return server.Serve(listener)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1", "bind address")
	cmd.Flags().IntVar(&port, "port", 8787, "bind port; use 0 for a random free port")
	cmd.Flags().BoolVar(&allowRemote, "allow-remote", false, "allow binding to non-local addresses")
	cmd.Flags().DurationVar(&lockAfter, "lock-after", 30*time.Minute, "idle duration before the web vault auto-locks; 0 disables")
	cmd.Flags().StringVar(&basicAuthUser, "basic-auth-user", "mnemox", "HTTP Basic Auth username for remote or explicitly protected web access")
	cmd.Flags().StringVar(&basicAuthPasswordFile, "basic-auth-password-file", "", "file containing the HTTP Basic Auth password")
	return cmd
}

func basicAuthConfig(enabled bool, username, passwordFile string) (*web.BasicAuth, error) {
	if !enabled {
		return nil, nil
	}
	if strings.TrimSpace(username) == "" {
		return nil, fmt.Errorf("--basic-auth-user is required when Basic Auth is enabled")
	}
	password, err := basicAuthPassword(passwordFile)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, fmt.Errorf("Basic Auth password cannot be empty")
	}
	if passwordFile != "" {
		return &web.BasicAuth{Username: username, PasswordFile: passwordFile}, nil
	}
	return &web.BasicAuth{Username: username, Password: password}, nil
}

func basicAuthPassword(passwordFile string) (string, error) {
	if passwordFile != "" {
		data, err := os.ReadFile(passwordFile) // #nosec G304 -- password file path is explicitly supplied by the operator.
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("--basic-auth-password-file is required when Basic Auth is enabled in a non-interactive terminal")
	}
	fmt.Print("Mnemox Basic Auth password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(password), "\r\n"), nil
}

func stringSlice(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func shortID(id string) string {
	if len(id) < 8 {
		return id
	}
	return id[:8]
}
