package vault

import (
	"fmt"
	"path/filepath"
	"testing"
)

func BenchmarkSearchCurrentVsV2Candidate(b *testing.B) {
	for _, size := range []int{1000, 5000, 20000} {
		b.Run(fmt.Sprintf("full-scan-%d", size), func(b *testing.B) {
			v := benchmarkVault(b, size)
			defer v.Close()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := v.Search("jenkins anonymous read", 10); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("v2-candidates-%d", size), func(b *testing.B) {
			v := benchmarkVault(b, size)
			defer v.Close()
			if _, err := v.MigrateV2(filepath.Join(b.TempDir(), "migration.mnemoxbak")); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := v.V2SearchCandidateIDs("jenkins anonymous read", 10); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkVault(b *testing.B, size int) *Vault {
	b.Helper()
	v, err := CreateWithPassphrase(filepath.Join(b.TempDir(), ".mnemox"), "Benchmark", "test-passphrase")
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < size; i++ {
		title := fmt.Sprintf("Finding %05d", i)
		if i%100 == 0 {
			title = fmt.Sprintf("Jenkins anonymous read %05d", i)
		}
		if _, err := v.AddRecord("finding", map[string]any{
			"title":          title,
			"status":         "confirmed",
			"affected_scope": []string{fmt.Sprintf("host-%05d.acme.local", i)},
			"summary":        "Generated benchmark record for local search performance.",
		}); err != nil {
			b.Fatal(err)
		}
	}
	return v
}
