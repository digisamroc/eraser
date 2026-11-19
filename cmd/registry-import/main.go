// Command registry-import regenerates data/brokers.yaml from the California
// CPPA data broker registry plus data/brokers.manual.yaml.
//
//	go run ./cmd/registry-import                 # download the current registry
//	go run ./cmd/registry-import -csv registry.csv -check-mx
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/eraser-privacy/eraser/internal/registry"
)

const maxDownload = 32 << 20

func main() {
	csvPath := flag.String("csv", "", "registry CSV file (default: download "+registry.RegistryURL+")")
	manualPath := flag.String("manual", "data/brokers.manual.yaml", "manual overlay file")
	outPath := flag.String("out", "data/brokers.yaml", "output broker database")
	checkMX := flag.Bool("check-mx", false, "drop brokers whose email domain has no MX or A record, and website/opt-out URLs whose host doesn't exist")
	reportPath := flag.String("report", "", "write a Markdown report of dropped and changed entries to this file")
	flag.Parse()

	if err := run(*csvPath, *manualPath, *outPath, *checkMX, *reportPath); err != nil {
		fmt.Fprintln(os.Stderr, "registry-import:", err)
		os.Exit(1)
	}
}

func run(csvPath, manualPath, outPath string, checkMX bool, reportPath string) error {
	raw, err := readRegistry(csvPath)
	if err != nil {
		return err
	}
	entries, err := registry.ParseCSV(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	manual, err := registry.LoadManual(manualPath)
	if err != nil {
		return err
	}

	var opts registry.Options
	if checkMX {
		opts.HasMailHost = resolveAll(emailDomains(entries), hasMailHost)
		opts.HostResolves = resolveAll(registry.URLHosts(entries, manual), hostExists)
	}

	db, rep, err := registry.Build(entries, manual, opts)
	if err != nil {
		return err
	}

	if err := registry.WriteDatabase(outPath, db); err != nil {
		return err
	}

	summary := formatReport(rep, len(db.Brokers))
	fmt.Fprint(os.Stderr, summary)
	if reportPath != "" {
		if err := os.WriteFile(reportPath, []byte(summary), 0o600); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
	}
	return nil
}

func readRegistry(path string) ([]byte, error) {
	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator's -csv flag
		if err != nil {
			return nil, fmt.Errorf("failed to read registry: %w", err)
		}
		return data, nil
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(registry.RegistryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download registry: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download registry: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, fmt.Errorf("failed to download registry: %w", err)
	}
	if len(data) > maxDownload {
		return nil, fmt.Errorf("registry download exceeds %d bytes", maxDownload)
	}
	return data, nil
}

func emailDomains(entries []registry.Entry) []string {
	var domains []string
	for _, e := range entries {
		addr := strings.ToLower(strings.TrimSpace(e.Email))
		if i := strings.LastIndex(addr, "@"); i >= 0 {
			domains = append(domains, addr[i+1:])
		}
	}
	return domains
}

// resolveAttempts is how many times a name must fail before it counts as
// missing. Under many parallel lookups the system resolver sometimes answers
// "no such host" for domains that exist (seen on macOS), and a wrong answer
// here drops a broker or a URL.
const resolveAttempts = 3

// retryDelay is the wait before the second attempt, doubled for the third.
var retryDelay = time.Second

// resolveAll checks every name concurrently up front and returns a lookup
// function over the results. A name only fails if every attempt fails.
func resolveAll(names []string, check func(string) bool) func(string) bool {
	results := make(map[string]bool, len(names))
	var unique []string // ranged over below: the goroutines write to results
	for _, n := range names {
		if _, dup := results[n]; !dup {
			results[n] = false
			unique = append(unique, n)
		}
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, 32)
	)
	for _, n := range unique {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ok := check(n)
			for attempt := 1; !ok && attempt < resolveAttempts; attempt++ {
				time.Sleep(time.Duration(attempt) * retryDelay)
				ok = check(n)
			}
			mu.Lock()
			results[n] = ok
			mu.Unlock()
		}(n)
	}
	wg.Wait()

	return func(name string) bool { return results[name] }
}

// hostExists reports whether host has an address record. Only a definite
// "no such host" counts as missing: a timeout or server failure keeps the
// URL, so a flaky resolver doesn't change the generated file.
func hostExists(host string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err == nil {
		return len(addrs) > 0
	}
	var dnsErr *net.DNSError
	return !errors.As(err, &dnsErr) || !dnsErr.IsNotFound
}

// hasMailHost follows RFC 5321: use MX records, or fall back to an A/AAAA record.
func hasMailHost(domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if mx, err := net.DefaultResolver.LookupMX(ctx, domain); err == nil && len(mx) > 0 {
		return len(mx) != 1 || mx[0].Host != "." // RFC 7505 null MX: accepts no mail
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
	return err == nil && len(addrs) > 0
}

func formatReport(rep registry.Report, kept int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Registry rows: %d\n", rep.Rows)
	fmt.Fprintf(&b, "Brokers written: %d (%d from the manual file)\n", kept, rep.Added)
	fmt.Fprintf(&b, "Merged (same email as another row): %d\n", rep.Merged)
	fmt.Fprintf(&b, "Overrides applied: %d\n", rep.Overridden)
	section := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s (%d):\n", title, len(items))
		for _, it := range items {
			fmt.Fprintf(&b, "- %s\n", it)
		}
	}
	section("Rejected", rep.Rejected)
	section("Excluded by manual file", rep.Excluded)
	section("No mail host", rep.NoMailHost)
	section("URLs dropped (host doesn't exist)", rep.DroppedURLs)
	section("Warnings", rep.Warnings)
	return b.String()
}
