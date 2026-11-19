package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/browser"
	"github.com/eraser-privacy/eraser/internal/config"
	"github.com/eraser-privacy/eraser/internal/email"
	"github.com/eraser-privacy/eraser/internal/history"
	"github.com/eraser-privacy/eraser/internal/inbox"
	"github.com/eraser-privacy/eraser/internal/registry"
	"github.com/eraser-privacy/eraser/internal/sendplan"
	"github.com/eraser-privacy/eraser/internal/template"
	"github.com/eraser-privacy/eraser/internal/web"
	"github.com/spf13/cobra"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/term"
)

var (
	cfgFile    string
	brokerFile string
	dryRun     bool
)

func resolveBrokerPath() string {
	if brokerFile != "" {
		return brokerFile
	}
	if _, err := os.Stat("data/brokers.yaml"); err == nil {
		return "data/brokers.yaml"
	}
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "data", "brokers.yaml")
}

func resolveConfigPath() string {
	if cfgFile != "" {
		return cfgFile
	}
	return config.DefaultConfigPath()
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "eraser",
		Short: "Eraser - Automated data broker removal requests",
		Long: `Eraser is an open-source tool that automates sending data removal
requests to data brokers, helping you protect your privacy.

It supports GDPR, CCPA, and generic removal request templates, and can
send via Gmail SMTP.`,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.eraser/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&brokerFile, "brokers", "", "broker database file (default is ./data/brokers.yaml)")

	// Add commands
	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(sendCmd())
	rootCmd.AddCommand(serveCmd())
	rootCmd.AddCommand(listBrokersCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(addBrokerCmd())
	rootCmd.AddCommand(monitorCmd())
	rootCmd.AddCommand(pipelineCmd())
	rootCmd.AddCommand(fillCmd())
	rootCmd.AddCommand(confirmCmd())
	rootCmd.AddCommand(cleanupBouncesCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize configuration interactively",
		Long:  "Create a new configuration file with your personal information and email settings.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit()
		},
	}
}

type sendFlags struct {
	yes         bool
	limit       int
	forceResend bool
}

func sendCmd() *cobra.Command {
	var flags sendFlags
	cmd := &cobra.Command{
		Use:   "send",
		Short: "Send removal requests to data brokers",
		Long: `Send data removal requests to the configured data brokers.

Brokers you successfully sent to within options.resend_after_days (default 30)
are skipped, and at most options.daily_limit (default 250) requests are sent
per rolling 24 hours, counting earlier runs. Asks for confirmation first.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSend(flags)
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview emails without sending")
	cmd.Flags().BoolVar(&flags.yes, "yes", false, "Send without asking for confirmation")
	cmd.Flags().IntVar(&flags.limit, "limit", 0, "Send to at most this many brokers in this run")
	cmd.Flags().BoolVar(&flags.forceResend, "force-resend", false, "Also send to brokers contacted within resend_after_days")

	return cmd
}

// confirmSend asks the user to type "yes". Without a terminal there is no one
// to ask, so it refuses rather than sending unattended.
func confirmSend(in io.Reader, out io.Writer, interactive bool, count int, fields []string) error {
	if !interactive {
		return fmt.Errorf("refusing to send without confirmation: stdin is not a terminal (pass --yes to send anyway)")
	}
	_, _ = fmt.Fprintf(out, "Send removal requests to %d brokers, disclosing %s? Type 'yes' to continue: ", count, strings.Join(fields, ", "))
	answer, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(strings.ToLower(answer)) != "yes" {
		return fmt.Errorf("cancelled; nothing was sent")
	}
	return nil
}

func listBrokersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-brokers",
		Short: "List all data brokers in the database",
		Long:  "Show all data brokers that will receive removal requests.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runListBrokers()
		},
	}
}

func statusCmd() *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show removal request history and statistics",
		Long:  "Display recent removal requests and overall statistics.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(limit)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 20, "Number of recent requests to show")

	return cmd
}

func addBrokerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add-broker",
		Short: "Add a new data broker to the database",
		Long:  "Interactively add a new data broker to the local broker database.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAddBroker()
		},
	}
}

func serveCmd() *cobra.Command {
	var port int

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the local web interface",
		Long: `Start a local web server providing a browser-based interface for Eraser.

This opens a visual dashboard where you can:
- Set up your profile and email settings
- Browse and manage data brokers
- Send removal requests with visual progress
- View history and statistics

The server runs locally on your machine - no data is sent to external servers.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(port)
		},
	}

	cmd.Flags().IntVar(&port, "port", 8080, "Port to listen on")

	return cmd
}

func runInit() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("🔐 Eraser Configuration Setup")
	fmt.Println("==============================")
	fmt.Println()

	cfg := &config.Config{}

	// Profile
	fmt.Println("📋 Personal Information (used in removal requests)")
	fmt.Println()

	cfg.Profile.FirstName = prompt(reader, "First name: ")
	cfg.Profile.LastName = prompt(reader, "Last name: ")
	cfg.Profile.Email = prompt(reader, "Email address: ")
	cfg.Profile.Address = prompt(reader, "Street address (optional): ")
	cfg.Profile.City = prompt(reader, "City (optional): ")
	cfg.Profile.State = prompt(reader, "State/Province (optional): ")
	cfg.Profile.ZipCode = prompt(reader, "ZIP/Postal code (optional): ")
	cfg.Profile.Country = prompt(reader, "Country (optional): ")
	cfg.Profile.Phone = prompt(reader, "Phone number (optional): ")

	fmt.Println()
	fmt.Println("📧 Email Settings")
	fmt.Println()

	cfg.Email.Provider = "smtp"
	cfg.Email.From = cfg.Profile.Email

	fmt.Println()
	fmt.Println("SMTP Configuration (any provider that offers SMTP works):")
	fmt.Println("  Gmail: press Enter for the defaults and use an app password")
	fmt.Println("  (see https://support.google.com/accounts/answer/185833)")
	fmt.Println()
	cfg.Email.SMTP = promptSMTP(reader)

	fmt.Println()
	fmt.Println("⚙️  Options")
	fmt.Println()

	templateChoice := prompt(reader, "Default template (gdpr/ccpa/generic) [generic]: ")
	if templateChoice == "" {
		templateChoice = "generic"
	}
	cfg.Options.Template = templateChoice
	cfg.Options.RateLimitMs = 2000

	configPath := resolveConfigPath()
	if err := config.Save(configPath, cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println()
	fmt.Printf("✅ Configuration saved to: %s\n", configPath)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Review and edit the config file if needed")
	fmt.Println("  2. Run 'eraser list-brokers' to see available brokers")
	fmt.Println("  3. Run 'eraser send --dry-run' to preview emails")
	fmt.Println("  4. Run 'eraser send' to send removal requests")

	return nil
}

func runSend(flags sendFlags) error {
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if flags.limit < 0 {
		return fmt.Errorf("--limit must not be negative")
	}

	// Override dry-run from command line
	if dryRun {
		cfg.Options.DryRun = true
	}

	brokerDB, err := broker.LoadFromFile(resolveBrokerPath())
	if err != nil {
		return fmt.Errorf("failed to load brokers: %w", err)
	}

	// Initialize template engine
	tmplEngine, err := template.NewEngine()
	if err != nil {
		return fmt.Errorf("failed to initialize templates: %w", err)
	}

	// Initialize history store
	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to initialize history: %w", err)
	}
	defer func() { _ = store.Close() }()

	// Plan the run (same rules as the web UI): config filters, resend
	// window, daily cap, and --limit.
	plan, err := sendplan.ForConfig(brokerDB.Brokers, cfg.Options, store, time.Now(), flags.limit, flags.forceResend)
	if err != nil {
		return err
	}
	brokers := plan.Send

	if cfg.Options.DryRun {
		fmt.Println("🔍 DRY RUN MODE - No emails will be sent")
		fmt.Println()
	}

	disclose, err := cfg.Options.Disclosure()
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	fmt.Printf("🔒 Sending: %s\n", strings.Join(disclose.Fields(), ", "))
	if withheld := disclose.Withheld(cfg.Profile); len(withheld) > 0 {
		fmt.Printf("   Withheld: %s (add to options.disclose to send; some brokers add more via their own disclose list)\n", strings.Join(withheld, ", "))
	}
	if n := len(plan.SkippedRecent); n > 0 {
		fmt.Printf("⏭️  Skipping %d brokers sent to in the last %d days (--force-resend to include)\n", n, cfg.Options.EffectiveResendAfterDays())
	}
	if plan.Deferred > 0 {
		reason := fmt.Sprintf("daily limit %d, %d already sent in the last 24h", cfg.Options.EffectiveDailyLimit(), plan.SentInWindow)
		if flags.limit > 0 && flags.limit < plan.RemainingToday {
			reason = fmt.Sprintf("--limit %d", flags.limit)
		}
		fmt.Printf("⏸️  Holding back %d brokers (%s). Run again later.\n", plan.Deferred, reason)
	}
	fmt.Println()

	if len(brokers) == 0 {
		fmt.Println("No brokers to process.")
		return nil
	}

	// Initialize email sender and confirm (unless dry-run)
	var sender email.Sender
	if !cfg.Options.DryRun {
		sender, err = email.NewSender(cfg.Email)
		if err != nil {
			return fmt.Errorf("failed to initialize email sender: %w", err)
		}
		if !flags.yes {
			if err := confirmSend(os.Stdin, os.Stdout, term.IsTerminal(int(os.Stdin.Fd())), len(brokers), disclose.Fields()); err != nil {
				return err
			}
			fmt.Println()
		}
	}

	deliverer := sendplan.Deliverer{Config: cfg, Engine: tmplEngine, Sender: sender, Store: store}

	// Ctrl-C stops between brokers instead of killing a send mid-conversation.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("📤 Processing %d brokers...\n", len(brokers))
	fmt.Println()

	successCount := 0
	failCount := 0

	for i, b := range brokers {
		if ctx.Err() != nil {
			fmt.Println("\n⛔ Interrupted; stopping.")
			break
		}
		fmt.Printf("[%d/%d] %s (%s)\n", i+1, len(brokers), b.Name, b.Email)

		if cfg.Options.DryRun {
			emailMsg, err := tmplEngine.Render(cfg.Options.Template, cfg.Profile, disclose, b)
			if err != nil {
				fmt.Printf("  ❌ Failed to render template: %v\n", err)
				failCount++
				continue
			}
			fmt.Printf("  📧 Would send: %s\n", emailMsg.Subject)
			fmt.Printf("  📍 To: %s\n", b.Email)
			if len(b.Disclose) > 0 {
				fmt.Printf("  🔓 This broker also gets: %s\n", strings.Join(b.Disclose, ", "))
			}
			successCount++
		} else {
			sendCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			record, err := deliverer.Deliver(sendCtx, disclose, b)
			cancel()
			if err != nil {
				// Without a history record this send would be repeated next
				// run and wouldn't count toward the daily limit, so stop.
				return fmt.Errorf("stopping to avoid duplicate sends: %w", err)
			}

			if record.Status == history.StatusSent {
				fmt.Printf("  ✅ Sent successfully\n")
				successCount++
			} else {
				fmt.Printf("  ❌ Failed: %s\n", record.Error)
				failCount++
			}

			// Rate limiting
			if i < len(brokers)-1 {
				select {
				case <-ctx.Done():
				case <-time.After(time.Duration(cfg.Options.RateLimitMs) * time.Millisecond):
				}
			}
		}
	}

	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if cfg.Options.DryRun {
		fmt.Printf("📊 Dry run complete: %d brokers would receive emails\n", successCount)
	} else {
		fmt.Printf("📊 Complete: %d sent, %d failed\n", successCount, failCount)
	}

	return nil
}

func runListBrokers() error {
	brokerDB, err := broker.LoadFromFile(resolveBrokerPath())
	if err != nil {
		return fmt.Errorf("failed to load brokers: %w", err)
	}

	fmt.Printf("📋 Data Brokers (%d total)\n", len(brokerDB.Brokers))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	for _, b := range brokerDB.Brokers {
		fmt.Printf("\n%s [%s]\n", b.Name, b.ID)
		fmt.Printf("  📧 %s\n", b.Email)
		if b.Website != "" {
			fmt.Printf("  🌐 %s\n", b.Website)
		}
		if b.OptOutURL != "" {
			fmt.Printf("  🔗 Opt-out: %s\n", b.OptOutURL)
		}
		fmt.Printf("  🌍 Region: %s\n", b.Region)
		if b.Category != "" {
			fmt.Printf("  📁 Category: %s\n", b.Category)
		}
	}

	return nil
}

func runStatus(limit int) error {
	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to open history: %w", err)
	}
	defer func() { _ = store.Close() }()

	// Get overall stats
	total, sent, failed, err := store.GetStats()
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	// Get monthly stats
	monthlySent, monthlyFailed, err := store.GetMonthlyStats()
	if err != nil {
		return fmt.Errorf("failed to get monthly stats: %w", err)
	}

	fmt.Println("📊 Eraser Statistics")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("All Time:")
	fmt.Printf("  Total requests: %d\n", total)
	fmt.Printf("  Sent: %d\n", sent)
	fmt.Printf("  Failed: %d\n", failed)
	fmt.Println()
	fmt.Println("This Month:")
	fmt.Printf("  Sent: %d\n", monthlySent)
	fmt.Printf("  Failed: %d\n", monthlyFailed)

	// Get recent requests
	records, err := store.GetRecentRequests(limit)
	if err != nil {
		return fmt.Errorf("failed to get recent requests: %w", err)
	}

	if len(records) > 0 {
		fmt.Println()
		fmt.Printf("📜 Recent Requests (last %d)\n", limit)
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		for _, r := range records {
			status := "✅"
			if r.Status == history.StatusFailed {
				status = "❌"
			}
			fmt.Printf("%s %s - %s (%s)\n",
				status,
				r.SentAt.Format("2006-01-02 15:04"),
				r.BrokerName,
				r.Template,
			)
			if r.Error != "" {
				fmt.Printf("   Error: %s\n", r.Error)
			}
		}
	}

	return nil
}

// manualPath is the hand-maintained overlay next to the broker database.
func manualPath(brokerPath string) string {
	return filepath.Join(filepath.Dir(brokerPath), "brokers.manual.yaml")
}

// runAddBroker records a broker in data/brokers.manual.yaml (so it survives
// regeneration from the registry) and adds it to data/brokers.yaml now.
func runAddBroker() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("➕ Add New Data Broker")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("Brokers registered in California are already in the list; this is for others.")
	fmt.Println()

	b := broker.Broker{Source: registry.SourceManual}
	b.Name = prompt(reader, "Broker name: ")
	b.ID = registry.Slug(b.Name)
	b.Email = strings.ToLower(prompt(reader, "Privacy/removal email: "))
	b.Website = prompt(reader, "Website (optional): ")
	b.OptOutURL = prompt(reader, "Opt-out URL (optional): ")
	b.Region = prompt(reader, "Region (us/eu/global) [us]: ")
	if b.Region == "" {
		b.Region = "us"
	}
	b.Category = prompt(reader, "Category (people-search/marketing/background-check/data-broker) [data-broker]: ")
	if b.Category == "" {
		b.Category = "data-broker"
	}
	b.SourceURL = prompt(reader, "Source URL (required; the https page where you found this contact): ")

	brokerPath := resolveBrokerPath()
	brokerDB, err := broker.LoadFromFile(brokerPath)
	if err != nil {
		return fmt.Errorf("failed to load brokers: %w", err)
	}
	if existing := brokerDB.FindByID(b.ID); existing != nil {
		return fmt.Errorf("a broker with ID %q already exists (%s)", b.ID, existing.Email)
	}
	if existing := brokerDB.FindByEmail(b.Email); existing != nil {
		return fmt.Errorf("%s already belongs to broker %q", b.Email, existing.ID)
	}

	// Validates the entry (email, personal mailbox, source URL) before writing.
	if err := registry.AddToManual(manualPath(brokerPath), b); err != nil {
		return err
	}
	brokerDB.Brokers = append(brokerDB.Brokers, b)
	if err := brokerDB.Validate(); err != nil {
		return err
	}
	if err := registry.WriteDatabase(brokerPath, brokerDB); err != nil {
		return fmt.Errorf("failed to save brokers: %w", err)
	}

	fmt.Println()
	fmt.Printf("✅ Added %s to %s and %s\n", b.Name, manualPath(brokerPath), brokerPath)
	return nil
}

func runServe(port int) error {
	configPath := resolveConfigPath()
	var cfg *config.Config
	if _, err := os.Stat(configPath); err == nil {
		cfg, err = config.Load(configPath)
		if err != nil {
			fmt.Printf("⚠️  Config exists but failed to load: %v\n", err)
			fmt.Println("The setup wizard will help you reconfigure.")
			cfg = nil
		}
	}

	brokerDB, err := broker.LoadFromFile(resolveBrokerPath())
	if err != nil {
		return fmt.Errorf("failed to load brokers: %w", err)
	}

	// Initialize history store
	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to initialize history: %w", err)
	}
	defer func() { _ = store.Close() }()

	// Initialize email template engine
	tmplEngine, err := template.NewEngine()
	if err != nil {
		return fmt.Errorf("failed to initialize templates: %w", err)
	}

	// Create and start web server
	server, err := web.NewServer(port, cfg, configPath, brokerDB, store, tmplEngine)
	if err != nil {
		return fmt.Errorf("failed to create web server: %w", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			fmt.Printf("Shutdown error: %v\n", err)
		}
	}()

	return server.Start()
}

// promptSMTP asks for the SMTP account, defaulting to Gmail. TLS is always on:
// implicit TLS on 465, STARTTLS on other ports.
func promptSMTP(reader *bufio.Reader) config.SMTPConfig {
	smtp := config.SMTPConfig{Host: "smtp.gmail.com", Port: 465, UseTLS: true}
	if host := prompt(reader, "  SMTP server [smtp.gmail.com]: "); host != "" {
		smtp.Host = host
	}
	for {
		answer := prompt(reader, "  Port (465 = TLS, 587 = STARTTLS) [465]: ")
		if answer == "" {
			break
		}
		if port, err := strconv.Atoi(answer); err == nil && port >= 1 && port <= 65535 {
			smtp.Port = port
			break
		}
		fmt.Println("  Enter a port between 1 and 65535.")
	}
	smtp.Username = prompt(reader, "  Username (usually your email address): ")
	smtp.Password = promptSecret(reader, "  Password (for Gmail, the app password; hidden): ")
	return smtp
}

func prompt(reader *bufio.Reader, message string) string {
	fmt.Print(message)
	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(input)
}

// promptSecret reads without echoing when stdin is a terminal, so the value
// doesn't appear on screen or in terminal scrollback.
func promptSecret(reader *bufio.Reader, message string) string {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return prompt(reader, message)
	}
	fmt.Print(message)
	input, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(input))
}

func monitorCmd() *cobra.Command {
	var days int
	var once bool
	var watch bool

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Monitor inbox for broker responses",
		Long: `Connect to your email inbox via IMAP and monitor for responses from data brokers.

This command will:
- Fetch recent emails from known broker domains
- Classify responses (form required, confirmation needed, success, etc.)
- Extract form URLs and confirmation links
- Store results for the pipeline to process

Requires inbox configuration in config.yaml with IMAP settings.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMonitor(days, once, watch)
		},
	}

	cmd.Flags().IntVar(&days, "days", 7, "Number of days to look back for emails")
	cmd.Flags().BoolVar(&once, "once", false, "Check inbox once and exit (don't watch for new emails)")
	cmd.Flags().BoolVar(&watch, "watch", false, "Continuously watch for new emails")

	return cmd
}

func pipelineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pipeline",
		Short: "Show pipeline status and statistics",
		Long:  "Display the current status of the removal pipeline, including pending tasks and response classifications.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPipelineStatus()
		},
	}

	return cmd
}

func runMonitor(days int, once bool, watch bool) error {
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Validate inbox config
	if err := cfg.ValidateInbox(); err != nil {
		fmt.Println("📧 Inbox monitoring is not configured.")
		fmt.Println()
		fmt.Println("To enable inbox monitoring, add the following to your config.yaml:")
		fmt.Println()
		fmt.Println("inbox:")
		fmt.Println("  enabled: true")
		fmt.Println("  provider: gmail")
		fmt.Println("  email: your-email@gmail.com")
		fmt.Println("  password: your-app-password  # Use an App Password, not your main password")
		fmt.Println()
		fmt.Println("For Gmail, you'll need to:")
		fmt.Println("  1. Enable 2-Step Verification")
		fmt.Println("  2. Generate an App Password at https://myaccount.google.com/apppasswords")
		fmt.Println("  3. Enable IMAP in Gmail settings")
		return err
	}

	// Load brokers for domain matching
	brokerDB, err := broker.LoadFromFile(resolveBrokerPath())
	if err != nil {
		return fmt.Errorf("failed to load brokers: %w", err)
	}

	// Initialize history store
	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to initialize history: %w", err)
	}
	defer func() { _ = store.Close() }()

	// Create inbox monitor; sent Message-IDs let it match replies by In-Reply-To.
	monitor := inbox.NewMonitor(cfg.Inbox, brokerDB.Brokers)
	warnIfSendersUnverified(monitor)
	if ids, err := store.SentMessageIDs(); err == nil {
		monitor.SetSentMessageIDs(ids)
	}

	// Connect to IMAP
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		cancel()
	}()

	if err := monitor.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to inbox: %w", err)
	}
	defer func() { _ = monitor.Disconnect() }()

	fmt.Printf("📬 Monitoring inbox for broker responses (last %d days)...\n", days)
	fmt.Println()

	// Fetch emails from known broker domains
	emails, err := monitor.FetchBrokerEmails(ctx, days)
	if err != nil {
		return fmt.Errorf("failed to fetch emails: %w", err)
	}

	if len(emails) == 0 {
		fmt.Println("No emails from known brokers found.")
		if !watch {
			return nil
		}
	}

	// Classify and process each email
	fmt.Printf("Found %d emails from data brokers\n", len(emails))
	fmt.Println()

	var responses []inbox.ClassifiedResponse
	for _, email := range emails {
		classified := inbox.ClassifyResponse(&email)
		responses = append(responses, classified)

		// Store (or update) the response; pipeline status only changes for
		// verified senders.
		if _, err := inbox.Record(store, &email, classified); err != nil {
			fmt.Printf("⚠️  Failed to store response: %v\n", err)
		}

		// Print summary
		printClassifiedResponse(classified)
	}

	// Archive processed emails if enabled
	if cfg.Inbox.AutoArchive && len(emails) > 0 {
		archiveFolder := cfg.Inbox.ArchiveFolder

		// Ensure archive folder exists
		if err := monitor.EnsureFolderExists(archiveFolder); err != nil {
			fmt.Printf("⚠️  Could not create archive folder: %v\n", err)
		} else if n, err := monitor.ArchiveEmails(emails, archiveFolder); err != nil {
			fmt.Printf("⚠️  Could not archive emails: %v\n", err)
		} else if n > 0 {
			fmt.Printf("📁 Archived %d emails to '%s'\n", n, archiveFolder)
		}
	}

	// Print summary
	summary := inbox.SummarizeResponses(responses)
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("📊 Summary:")
	fmt.Printf("  Total responses:     %d\n", summary.Total)
	fmt.Printf("  ✅ Success:          %d\n", summary.Success)
	fmt.Printf("  📝 Form required:    %d\n", summary.FormRequired)
	fmt.Printf("  🔗 Confirm required: %d\n", summary.ConfirmRequired)
	fmt.Printf("  ❌ Rejected:         %d\n", summary.Rejected)
	fmt.Printf("  ⏳ Pending:          %d\n", summary.Pending)
	fmt.Printf("  ❓ Unknown:          %d\n", summary.Unknown)
	fmt.Printf("  👁️  Need review:      %d\n", summary.NeedReview)

	if once {
		return nil
	}

	// Watch for new emails if requested
	if watch {
		fmt.Println()
		fmt.Println("👀 Watching for new emails... (Ctrl+C to stop)")

		err := monitor.WatchForNewEmails(ctx, func(email inbox.Email) {
			fmt.Println()
			fmt.Printf("📨 New email from %s (%s)\n", email.BrokerName, email.From)

			classified := inbox.ClassifyResponse(&email)
			printClassifiedResponse(classified)

			if _, err := inbox.Record(store, &email, classified); err != nil {
				fmt.Printf("⚠️  Failed to store response: %v\n", err)
			}
		})

		if err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("watch error: %w", err)
		}
	}

	return nil
}

func printClassifiedResponse(r inbox.ClassifiedResponse) {
	var icon string
	switch r.Type {
	case inbox.ResponseSuccess:
		icon = "✅"
	case inbox.ResponseFormRequired:
		icon = "📝"
	case inbox.ResponseConfirmationRequired:
		icon = "🔗"
	case inbox.ResponseRejected:
		icon = "❌"
	case inbox.ResponsePending:
		icon = "⏳"
	case inbox.ResponseInfoRequired:
		icon = "🔎"
	default:
		icon = "❓"
	}

	fmt.Printf("%s %s - %s\n", icon, r.Email.BrokerName, r.Type)
	if !r.Email.Authenticated {
		fmt.Printf("   ⚠️  Sender not verified by your mail provider; links ignored\n")
	}
	if r.Type == inbox.ResponseInfoRequired {
		fmt.Printf("   🔎 Broker wants more details. If you agree, add a disclose override for %s in data/brokers.manual.yaml\n", r.Email.BrokerID)
	}
	fmt.Printf("   Subject: %s\n", r.Email.Subject)

	if r.FormURL != "" {
		fmt.Printf("   📝 Form URL: %s\n", r.FormURL)
	}
	if r.ConfirmURL != "" {
		fmt.Printf("   🔗 Confirm URL: %s\n", r.ConfirmURL)
	}
	if r.NeedsReview {
		fmt.Printf("   ⚠️  Confidence: %.0f%% - manual review recommended\n", r.Confidence*100)
	}
}

func runPipelineStatus() error {
	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to open history: %w", err)
	}
	defer func() { _ = store.Close() }()

	fmt.Println("🔄 Pipeline Status")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// Get pipeline stats
	pipelineStats, err := store.GetPipelineStats()
	if err != nil {
		return fmt.Errorf("failed to get pipeline stats: %w", err)
	}

	fmt.Println("📊 Pipeline Stage Breakdown:")
	fmt.Printf("  📧 Email sent:            %d\n", pipelineStats[history.PipelineEmailSent])
	fmt.Printf("  ⏳ Awaiting response:     %d\n", pipelineStats[history.PipelineAwaitingResponse])
	fmt.Printf("  📝 Form required:         %d\n", pipelineStats[history.PipelineFormRequired])
	fmt.Printf("  ✏️  Form filled:           %d\n", pipelineStats[history.PipelineFormFilled])
	fmt.Printf("  🤖 Awaiting CAPTCHA:      %d\n", pipelineStats[history.PipelineAwaitingCaptcha])
	fmt.Printf("  ✅ CAPTCHA solved:        %d\n", pipelineStats[history.PipelineCaptchaSolved])
	fmt.Printf("  🔗 Awaiting confirmation: %d\n", pipelineStats[history.PipelineAwaitingConfirmation])
	fmt.Printf("  ✅ Confirmed:             %d\n", pipelineStats[history.PipelineConfirmed])
	fmt.Printf("  🔎 Info required:         %d\n", pipelineStats[history.PipelineInfoRequired])
	fmt.Printf("  ❌ Rejected:              %d\n", pipelineStats[history.PipelineRejected])
	fmt.Printf("  💥 Failed:                %d\n", pipelineStats[history.PipelineFailed])

	// Get response stats
	responseStats, err := store.GetResponseStats()
	if err != nil {
		fmt.Printf("\n⚠️  Could not get response stats: %v\n", err)
	} else if len(responseStats) > 0 {
		fmt.Println()
		fmt.Println("📬 Response Classification:")
		for responseType, count := range responseStats {
			fmt.Printf("  %s: %d\n", responseType, count)
		}
	}

	// Get pending tasks
	pending, completed, skipped, err := store.GetPendingTaskStats()
	if err != nil {
		fmt.Printf("\n⚠️  Could not get task stats: %v\n", err)
	} else if pending+completed+skipped > 0 {
		fmt.Println()
		fmt.Println("📋 Pending Tasks:")
		fmt.Printf("  ⏳ Pending:   %d\n", pending)
		fmt.Printf("  ✅ Completed: %d\n", completed)
		fmt.Printf("  ⏭️  Skipped:   %d\n", skipped)
	}

	// Show actionable items
	tasks, err := store.GetPendingTasks("", "pending")
	if err == nil && len(tasks) > 0 {
		fmt.Println()
		fmt.Println("🎯 Action Required:")
		for _, task := range tasks {
			fmt.Printf("  • %s [%s] - %s\n", task.BrokerName, task.TaskType, task.FormURL)
		}
	}

	return nil
}

func fillCmd() *cobra.Command {
	var o fillOptions

	cmd := &cobra.Command{
		Use:   "fill",
		Short: "Fill opt-out forms using browser automation",
		Long: `Navigate to data broker opt-out forms and automatically fill them using your profile data.

This command uses headless Chrome to:
- Navigate to opt-out form URLs
- Detect and fill form fields with the profile fields you disclose to that broker
- Detect CAPTCHAs (creates tasks for manual solving)
- Optionally submit the form

Safety: forms are only filled on https pages on the broker's own domain
(checked again after redirects). Form links from your inbox are only used
when the sender was verified.

Examples:
  # Fill a specific form URL
  eraser fill --url "https://example.com/optout"

  # Fill form for a specific broker (using URL from pipeline)
  eraser fill --broker spokeo

  # Fill all pending forms from the pipeline
  eraser fill --pending

  # Fill with visible browser window (for debugging)
  eraser fill --url "https://example.com/optout" --headless=false

  # Fill form and wait for you to solve CAPTCHA, then auto-submit
  eraser fill --url "https://example.com/optout" --headless=false --wait --submit`,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.headlessSet = cmd.Flags().Changed("headless")
			return runFill(o)
		},
	}

	cmd.Flags().StringVar(&o.brokerID, "broker", "", "Broker ID to fill form for (uses URL from pipeline)")
	cmd.Flags().StringVar(&o.formURL, "url", "", "Direct URL to the opt-out form")
	cmd.Flags().BoolVar(&o.headless, "headless", true, "Run browser in headless mode (default: pipeline.browser_headless, true)")
	cmd.Flags().BoolVar(&o.submit, "submit", false, "Automatically submit the form after filling")
	cmd.Flags().StringVar(&o.screenshotDir, "screenshots", "", "Directory to save screenshots (default: ~/.eraser/screenshots)")
	cmd.Flags().BoolVar(&o.pending, "pending", false, "Fill all pending forms from the pipeline")
	cmd.Flags().BoolVar(&o.wait, "wait", false, "Wait for user to solve CAPTCHA before continuing (use with --headless=false)")
	cmd.Flags().BoolVar(&o.allowOtherSite, "allow-other-domain", false, "With --url and --broker: allow a typed URL that isn't on the broker's domain")

	return cmd
}

// fillJob is one form to fill, with the check its pages must pass.
type fillJob struct {
	brokerID string
	broker   *broker.Broker // nil for a URL the user typed without --broker
	url      string
	allowed  func(*url.URL) bool
}

// fillProfile returns the profile fields this broker may receive: the global
// disclose setting plus the broker's own disclose list.
func fillProfile(cfg *config.Config, b *broker.Broker) (config.Profile, error) {
	disclose, err := cfg.Options.Disclosure()
	if err != nil {
		return config.Profile{}, err
	}
	if b != nil {
		extra, err := config.ParseDisclosure(b.Disclose)
		if err != nil {
			return config.Profile{}, err
		}
		disclose = disclose.Union(extra)
	}
	return disclose.Apply(cfg.Profile), nil
}

// brokerAllowed only allows https pages the broker owns.
func brokerAllowed(b *broker.Broker) func(*url.URL) bool {
	return func(u *url.URL) bool { return b.OwnsURL(u.String()) }
}

// typedURLAllowed allows https pages on the same site as a URL the user typed.
func typedURLAllowed(raw string) (func(*url.URL) bool, error) {
	typed, err := url.Parse(raw)
	if err != nil || typed.Scheme != "https" || typed.Hostname() == "" {
		return nil, fmt.Errorf("form URL must be https: %s", raw)
	}
	site, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(typed.Hostname()))
	if err != nil {
		return nil, fmt.Errorf("invalid form URL host: %s", raw)
	}
	return func(u *url.URL) bool {
		org, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(u.Hostname()))
		return err == nil && u.Scheme == "https" && org == site
	}, nil
}

type fillOptions struct {
	brokerID, formURL, screenshotDir      string
	headless, headlessSet                 bool
	submit, pending, wait, allowOtherSite bool
}

func runFill(o fillOptions) error {
	// Load config for profile data
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if _, err := cfg.Options.Disclosure(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	brokerDB, err := broker.LoadFromFile(resolveBrokerPath())
	if err != nil {
		return fmt.Errorf("failed to load brokers: %w", err)
	}

	// Screenshots show filled-in personal details: keep the default folder
	// private, including one created by older versions with 0755.
	screenshotDir := o.screenshotDir
	if screenshotDir == "" {
		home, _ := os.UserHomeDir()
		screenshotDir = filepath.Join(home, ".eraser", "screenshots")
		if err := os.MkdirAll(screenshotDir, 0o700); err != nil {
			return fmt.Errorf("failed to create screenshot folder: %w", err)
		}
		if err := os.Chmod(screenshotDir, 0o700); err != nil { //nolint:gosec // G302: a directory needs x; 0700 is owner-only
			return fmt.Errorf("failed to secure screenshot folder: %w", err)
		}
	}

	// Initialize history store
	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to initialize history: %w", err)
	}
	defer func() { _ = store.Close() }()

	jobs, err := fillJobs(o, brokerDB, store)
	if err != nil {
		return err
	}
	if len(jobs) == 0 {
		fmt.Println("✅ No pending forms to fill")
		return nil
	}

	// Create browser config
	headless := cfg.Pipeline.Headless()
	if o.headlessSet {
		headless = o.headless
	}
	browserCfg := browser.DefaultConfig()
	browserCfg.Headless = headless
	browserCfg.ScreenshotDir = screenshotDir
	if cfg.Pipeline.BrowserTimeoutSec > 0 {
		browserCfg.Timeout = time.Duration(cfg.Pipeline.BrowserTimeoutSec) * time.Second
	}

	// Set up wait for CAPTCHA if requested
	if o.wait {
		if headless {
			fmt.Println("⚠️  Warning: --wait requires --headless=false to be useful")
		}
		browserCfg.WaitForUser = true
		browserCfg.Timeout = 5 * time.Minute // Longer timeout when waiting for user
		browserCfg.WaitCallback = func() error {
			fmt.Println()
			fmt.Println("       ⏸️  CAPTCHA detected! Solve it in the browser window.")
			fmt.Println("       Press ENTER when done (or Ctrl+C to cancel)...")
			fmt.Println()
			reader := bufio.NewReader(os.Stdin)
			_, err := reader.ReadString('\n')
			return err
		}
	}

	b, err := browser.New(browserCfg)
	if err != nil {
		return fmt.Errorf("failed to create browser: %w", err)
	}
	defer b.Close()

	fmt.Println("🌐 Browser Automation")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Printf("📋 Forms to process: %d\n", len(jobs))
	fmt.Println()

	for i, job := range jobs {
		fmt.Printf("[%d/%d] Processing %s\n", i+1, len(jobs), job.url)
		if job.brokerID != "" {
			fmt.Printf("       Broker: %s\n", job.brokerID)
		}

		profile, err := fillProfile(cfg, job.broker)
		if err != nil {
			return fmt.Errorf("invalid disclose setting: %w", err)
		}

		result, err := b.NavigateAndFill(browser.FillRequest{
			URL: job.url, BrokerID: job.brokerID, Profile: profile,
			Allowed: job.allowed, Submit: o.submit,
		})
		if err != nil {
			fmt.Printf("       ❌ Error: %v\n", err)
			continue
		}

		if len(result.FieldsFilled) > 0 {
			fmt.Printf("       ✅ Filled fields: %s\n", strings.Join(result.FieldsFilled, ", "))
		}
		if len(result.FieldsMissing) > 0 {
			fmt.Printf("       ℹ️  Not filled (not disclosed, or not in your profile): %s\n", strings.Join(result.FieldsMissing, ", "))
		}

		switch {
		case result.CaptchaFound:
			fmt.Printf("       🤖 CAPTCHA detected: %s\n", result.CaptchaType)

			// The helper page shows only what this broker may receive.
			profileJSON, _ := json.Marshal(map[string]string{
				"email": profile.Email, "firstName": profile.FirstName, "lastName": profile.LastName,
				"phone": profile.Phone, "address": profile.Address, "city": profile.City,
				"state": profile.State, "zipCode": profile.ZipCode, "country": profile.Country,
			})
			task := &history.PendingTask{
				BrokerID:       job.brokerID,
				BrokerName:     job.brokerID,
				TaskType:       history.TaskCaptcha,
				FormURL:        job.url,
				BrowserState:   string(profileJSON),
				Status:         "pending",
				ScreenshotPath: result.ScreenshotPath,
			}
			if err := store.AddPendingTask(task); err != nil {
				fmt.Printf("       ⚠️  Failed to create task: %v\n", err)
			} else {
				fmt.Printf("       📝 Created CAPTCHA task for manual solving\n")
			}
			_ = store.UpdatePipelineStatus(job.brokerID, history.PipelineAwaitingCaptcha)
		case result.SubmitAttempted:
			fmt.Printf("       📨 Form submitted\n")
			_ = store.UpdatePipelineStatus(job.brokerID, history.PipelineFormFilled)
		case result.ErrorMessage != "":
			fmt.Printf("       ⚠️  %s\n", result.ErrorMessage)
		case result.Success:
			fmt.Printf("       ✅ Form filled (not submitted; use --submit, or --headless=false to review)\n")
		}

		if result.ScreenshotPath != "" {
			fmt.Printf("       📸 Screenshot: %s\n", result.ScreenshotPath)
		}
		fmt.Println()

		// Small delay between forms to be respectful
		if i < len(jobs)-1 {
			time.Sleep(2 * time.Second)
		}
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("✅ Processed %d forms\n", len(jobs))
	return nil
}

// fillJobs decides which forms to fill and what each may reach. URLs from
// the inbox must come from a verified sender and belong to the broker, with
// no override; only a URL the user typed can use --allow-other-domain.
func fillJobs(o fillOptions, brokerDB *broker.BrokerDatabase, store *history.Store) ([]fillJob, error) {
	if o.formURL != "" {
		if o.brokerID == "" {
			allowed, err := typedURLAllowed(o.formURL)
			if err != nil {
				return nil, err
			}
			return []fillJob{{url: o.formURL, allowed: allowed}}, nil
		}
		b := brokerDB.FindByID(o.brokerID)
		if b == nil {
			return nil, fmt.Errorf("unknown broker: %s", o.brokerID)
		}
		allowed := brokerAllowed(b)
		if !b.OwnsURL(o.formURL) {
			if !o.allowOtherSite {
				return nil, fmt.Errorf("%s is not on %s's domain; check the URL, or pass --allow-other-domain if you're sure", o.formURL, b.ID)
			}
			if allowed, _ = typedURLAllowed(o.formURL); allowed == nil {
				return nil, fmt.Errorf("form URL must be https: %s", o.formURL)
			}
		}
		return []fillJob{{brokerID: b.ID, broker: b, url: o.formURL, allowed: allowed}}, nil
	}

	if o.brokerID == "" && !o.pending {
		return nil, fmt.Errorf("please specify --url, --broker, or --pending")
	}
	responses, err := store.GetBrokerResponses("form_required", false, 100)
	if err != nil {
		return nil, fmt.Errorf("failed to get broker responses: %w", err)
	}
	var jobs []fillJob
	for _, resp := range responses {
		if resp.FormURL == "" || (o.brokerID != "" && resp.BrokerID != o.brokerID) {
			continue
		}
		b := brokerDB.FindByID(resp.BrokerID)
		switch {
		case !resp.Authenticated:
			fmt.Printf("⏭️  %s: skipping a form link from an unverified email\n", resp.BrokerID)
			continue
		case b == nil:
			fmt.Printf("⏭️  %s: broker no longer in the list; skipping\n", resp.BrokerID)
			continue
		case !b.OwnsURL(resp.FormURL):
			fmt.Printf("⏭️  %s: form link %s is not on the broker's domain; open it yourself if you trust it\n", b.ID, resp.FormURL)
			continue
		}
		jobs = append(jobs, fillJob{brokerID: b.ID, broker: b, url: resp.FormURL, allowed: brokerAllowed(b)})
		if o.brokerID != "" {
			break
		}
	}
	if o.brokerID != "" && len(jobs) == 0 {
		return nil, fmt.Errorf("no usable form URL found for broker: %s", o.brokerID)
	}
	return jobs, nil
}

func confirmCmd() *cobra.Command {
	var confirmURL string
	var brokerID string
	var pending bool
	var validateDomain bool
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "confirm",
		Short: "Click confirmation links from broker emails",
		Long: `Automatically click confirmation links received from data brokers.

This command makes HTTP GET requests to confirmation URLs to complete the opt-out process.
It follows redirects and verifies success based on the response content.

Examples:
  # Confirm a specific URL
  eraser confirm --url "https://broker.com/confirm?token=abc123"

  # Confirm for a specific broker (using URL from pipeline)
  eraser confirm --broker spokeo

  # Confirm all pending confirmation links
  eraser confirm --pending

  # Preview without actually clicking (dry run)
  eraser confirm --pending --dry-run

Safety features:
  - Domain validation ensures links are from known broker domains
  - Follows redirects up to 10 hops
  - Detects success/failure from response content`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfirm(confirmURL, brokerID, pending, validateDomain, dryRun)
		},
	}

	cmd.Flags().StringVar(&confirmURL, "url", "", "Direct confirmation URL to click")
	cmd.Flags().StringVar(&brokerID, "broker", "", "Broker ID to confirm for (uses URL from pipeline)")
	cmd.Flags().BoolVar(&pending, "pending", false, "Confirm all pending confirmation links")
	cmd.Flags().BoolVar(&validateDomain, "validate-domain", true, "Validate URL domain against known brokers")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview links without clicking them")

	return cmd
}

// confirmLink is one confirmation link and the check every hop must pass.
type confirmLink struct {
	brokerID string
	url      string
	allowed  func(*url.URL) bool
}

func runConfirm(confirmURL, brokerID string, pending, validateDomain, dryRun bool) error {
	// Load brokers for domain validation
	brokerDB, err := broker.LoadFromFile(resolveBrokerPath())
	if err != nil {
		return fmt.Errorf("failed to load brokers: %w", err)
	}

	// Initialize history store
	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to initialize history: %w", err)
	}
	defer func() { _ = store.Close() }()

	handler := browser.NewConfirmationHandler()

	fmt.Println("🔗 Confirmation Link Handler")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	var links []confirmLink
	switch {
	case confirmURL != "" && brokerID != "":
		b := brokerDB.FindByID(brokerID)
		if b == nil {
			return fmt.Errorf("unknown broker: %s", brokerID)
		}
		links = append(links, confirmLink{brokerID: b.ID, url: confirmURL, allowed: brokerAllowed(b)})
	case confirmURL != "":
		// A link the user typed, with no broker: it must be on some broker's
		// domain (unless --validate-domain=false), and redirects must stay
		// on that site.
		site, err := typedURLAllowed(confirmURL)
		if err != nil {
			return err
		}
		allowed := site
		if validateDomain {
			allowed = func(u *url.URL) bool { return site(u) && anyBrokerOwns(brokerDB, u) }
		}
		links = append(links, confirmLink{url: confirmURL, allowed: allowed})
	case brokerID != "" || pending:
		responses, err := store.GetBrokerResponses("confirmation_required", false, 100)
		if err != nil {
			return fmt.Errorf("failed to get broker responses: %w", err)
		}
		for _, resp := range responses {
			if resp.ConfirmURL == "" || (brokerID != "" && resp.BrokerID != brokerID) {
				continue
			}
			b := brokerDB.FindByID(resp.BrokerID)
			switch {
			case !resp.Authenticated:
				fmt.Printf("⏭️  %s: skipping a link from an unverified email\n", resp.BrokerID)
				continue
			case b == nil:
				fmt.Printf("⏭️  %s: broker no longer in the list; skipping\n", resp.BrokerID)
				continue
			}
			links = append(links, confirmLink{brokerID: b.ID, url: resp.ConfirmURL, allowed: brokerAllowed(b)})
			if brokerID != "" {
				break
			}
		}
		if brokerID != "" && len(links) == 0 {
			return fmt.Errorf("no usable confirmation URL found for broker: %s", brokerID)
		}
		if len(links) == 0 {
			fmt.Println("✅ No pending confirmation links")
			return nil
		}
	default:
		return fmt.Errorf("please specify --url, --broker, or --pending")
	}

	fmt.Printf("📋 Confirmation links to process: %d\n", len(links))
	if dryRun {
		fmt.Println("🔍 DRY RUN MODE - Links will not be clicked")
	}
	fmt.Println()

	successCount := 0
	failCount := 0
	unclearCount := 0

	for i, link := range links {
		fmt.Printf("[%d/%d] Processing confirmation link\n", i+1, len(links))
		if link.brokerID != "" {
			fmt.Printf("       Broker: %s\n", link.brokerID)
		}
		fmt.Printf("       URL: %s\n", truncateURL(link.url, 60))

		if u, err := url.Parse(link.url); err != nil || !link.allowed(u) {
			fmt.Printf("       ⚠️  Not on the broker's domain (or not https); not clicking\n")
			failCount++
			fmt.Println()
			continue
		}

		if dryRun {
			fmt.Printf("       📋 Would click this link (dry run)\n")
			successCount++
			fmt.Println()
			continue
		}

		// Every redirect hop must pass the same check.
		result, err := handler.ClickConfirmationLink(link.url, link.allowed)
		if err != nil {
			fmt.Printf("       ❌ Error: %v\n", err)
			failCount++
			fmt.Println()
			continue
		}

		fmt.Printf("       HTTP Status: %d\n", result.StatusCode)
		if len(result.RedirectPath) > 1 {
			fmt.Printf("       Redirects: %d hops\n", len(result.RedirectPath)-1)
		}
		if result.FinalURL != link.url {
			fmt.Printf("       Final URL: %s\n", truncateURL(result.FinalURL, 60))
		}

		// Only a clear answer changes the broker's status.
		status := handler.ExtractConfirmationStatus(result)
		switch result.Outcome {
		case browser.ConfirmConfirmed:
			fmt.Printf("       ✅ %s\n", status)
			successCount++
			if link.brokerID != "" {
				_ = store.UpdatePipelineStatus(link.brokerID, history.PipelineConfirmed)
			}
		case browser.ConfirmFailed:
			fmt.Printf("       ❌ %s\n", status)
			failCount++
			if link.brokerID != "" {
				_ = store.UpdatePipelineStatus(link.brokerID, history.PipelineFailed)
			}
		default:
			fmt.Printf("       ❓ %s\n", status)
			unclearCount++
		}

		fmt.Println()

		// Small delay between confirmations
		if i < len(links)-1 {
			time.Sleep(1 * time.Second)
		}
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if dryRun {
		fmt.Printf("📊 Dry run complete: %d links would be clicked\n", len(links))
	} else {
		fmt.Printf("📊 Complete: %d confirmed, %d failed, %d unclear\n", successCount, failCount, unclearCount)
	}

	return nil
}

// anyBrokerOwns reports whether some broker in the list owns u.
func anyBrokerOwns(db *broker.BrokerDatabase, u *url.URL) bool {
	for _, b := range db.Brokers {
		if b.OwnsURL(u.String()) {
			return true
		}
	}
	return false
}

// truncateURL truncates a URL to the specified length for display
func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return url[:maxLen-3] + "..."
}

func cleanupBouncesCmd() *cobra.Command {
	var (
		remove bool
		days   int
	)

	cmd := &cobra.Command{
		Use:   "cleanup-bounces",
		Short: "Find and remove bounced broker email addresses",
		Long: `Scan your inbox for bounced/undeliverable emails and identify
invalid broker email addresses. Optionally remove them from the database.

By default, this command shows what would be removed without making changes.
Use --remove to actually remove the invalid brokers from the database.

Examples:
  eraser cleanup-bounces                 # Show bounced emails (dry run)
  eraser cleanup-bounces --remove        # Remove bounced brokers
  eraser cleanup-bounces --days 30       # Look back 30 days`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCleanupBounces(remove, days)
		},
	}

	cmd.Flags().BoolVar(&remove, "remove", false, "Actually remove bounced brokers from database")
	cmd.Flags().IntVar(&days, "days", 30, "Number of days to scan for bounced emails")

	return cmd
}

func runCleanupBounces(remove bool, days int) error {
	// Load config
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Check if inbox is configured
	if !cfg.Inbox.Enabled {
		return fmt.Errorf("inbox monitoring not configured. Run 'eraser init' to set up")
	}

	// Load broker database
	brokerPath := resolveBrokerPath()
	brokerDB, err := broker.LoadFromFile(brokerPath)
	if err != nil {
		return fmt.Errorf("failed to load brokers: %w", err)
	}

	fmt.Println("🔍 Scanning inbox for bounced emails...")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// Bounces are matched to the requests they refer to by Message-ID.
	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to initialize history: %w", err)
	}
	defer func() { _ = store.Close() }()
	sentIDs, err := store.SentMessageIDs()
	if err != nil {
		return fmt.Errorf("failed to read sent requests: %w", err)
	}

	// Create inbox monitor
	monitor := inbox.NewMonitor(cfg.Inbox, brokerDB.Brokers)
	warnIfSendersUnverified(monitor)

	// Connect
	ctx := context.Background()
	if err := monitor.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to inbox: %w", err)
	}
	defer func() { _ = monitor.Disconnect() }()

	// Fetch bounce emails
	bounceEmails, err := monitor.FetchBounceEmails(ctx, days)
	if err != nil {
		return fmt.Errorf("failed to fetch bounce emails: %w", err)
	}

	if len(bounceEmails) == 0 {
		fmt.Println("✓ No bounced emails found!")
		return nil
	}

	fmt.Printf("Found %d bounced email(s):\n\n", len(bounceEmails))

	// Track brokers to remove
	type bouncedBroker struct {
		email      string
		broker     *broker.Broker
		subject    string
		receivedAt time.Time
	}
	var bouncedBrokers []bouncedBroker

	for _, email := range bounceEmails {
		// Only a verified bounce of a request we sent counts; otherwise a
		// forged "undeliverable" email could remove a broker from your list.
		b, err := inbox.VerifyBounce(&email, sentIDs, brokerDB)
		if err != nil {
			fmt.Printf("⚠️  %s (%s): %v; skipping\n", truncateString(email.Subject, 60), email.From, err)
			continue
		}
		bouncedRecipient := b.Email

		fmt.Printf("❌ %s\n", bouncedRecipient)
		fmt.Printf("   Broker: %s (%s)\n", b.Name, b.ID)
		fmt.Printf("   Subject: %s\n", truncateString(email.Subject, 60))
		fmt.Printf("   Date: %s\n", email.ReceivedAt.Format("2006-01-02"))
		fmt.Println()

		bouncedBrokers = append(bouncedBrokers, bouncedBroker{
			email:      bouncedRecipient,
			broker:     b,
			subject:    email.Subject,
			receivedAt: email.ReceivedAt,
		})
	}

	if len(bouncedBrokers) == 0 {
		fmt.Println("✓ No broker email addresses need to be removed")
		return nil
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if !remove {
		fmt.Printf("\n📊 Found %d broker(s) with invalid email addresses\n", len(bouncedBrokers))
		fmt.Println("Run with --remove to delete these brokers from the database")
		return nil
	}

	// Record exclusions in the manual file (so regeneration keeps them) and
	// drop the brokers from the database now.
	fmt.Printf("\n🗑️  Removing %d broker(s)...\n\n", len(bouncedBrokers))

	var exclusions []registry.Exclusion
	bounced := make(map[string]bool)
	for _, bb := range bouncedBrokers {
		exclusions = append(exclusions, registry.Exclusion{
			Email:    bb.email,
			Reason:   "Bounced: " + truncateString(bb.subject, 80),
			Evidence: "Bounce notification received " + bb.receivedAt.Format("2006-01-02"),
		})
		bounced[strings.ToLower(bb.email)] = true
	}
	if err := registry.ExcludeInManual(manualPath(brokerPath), exclusions); err != nil {
		return err
	}
	before := len(brokerDB.Brokers)
	brokerDB.Brokers = slices.DeleteFunc(brokerDB.Brokers, func(b broker.Broker) bool {
		return bounced[strings.ToLower(b.Email)]
	})
	if err := registry.WriteDatabase(brokerPath, brokerDB); err != nil {
		return fmt.Errorf("failed to save broker database: %w", err)
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("✓ Removed %d broker(s); exclusions recorded in %s\n", before-len(brokerDB.Brokers), manualPath(brokerPath))
	return nil
}

// warnIfSendersUnverified explains that, without a known authserv-id, no
// email counts as verified.
func warnIfSendersUnverified(m *inbox.Monitor) {
	if !m.VerifiesSenders() {
		fmt.Println("⚠️  Can't verify senders: set inbox.authserv_id in config.yaml (see config.example.yaml).")
		fmt.Println("   Until then, links in broker email are ignored and bounces can't remove brokers.")
		fmt.Println()
	}
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
