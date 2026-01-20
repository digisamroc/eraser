package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/eraser-privacy/eraser/internal/broker"
	"github.com/eraser-privacy/eraser/internal/browser"
	"github.com/eraser-privacy/eraser/internal/config"
	"github.com/eraser-privacy/eraser/internal/email"
	"github.com/eraser-privacy/eraser/internal/history"
	"github.com/eraser-privacy/eraser/internal/inbox"
	"github.com/eraser-privacy/eraser/internal/template"
	"github.com/eraser-privacy/eraser/internal/web"
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

func sendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send",
		Short: "Send removal requests to data brokers",
		Long:  "Send data removal requests to all configured data brokers.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSend()
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview emails without sending")

	return cmd
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
	fmt.Println("Gmail SMTP Configuration:")
	fmt.Println("  (See https://support.google.com/accounts/answer/185833 for app password setup)")
	fmt.Println()
	cfg.Email.SMTP.Host = "smtp.gmail.com"
	cfg.Email.SMTP.Port = 465
	cfg.Email.SMTP.UseTLS = true
	cfg.Email.SMTP.Username = prompt(reader, "  Gmail address: ")
	cfg.Email.SMTP.Password = prompt(reader, "  App password (16-character code): ")

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

func runSend() error {
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// Override dry-run from command line
	if dryRun {
		cfg.Options.DryRun = true
	}

	brokerDB, err := broker.LoadFromFile(resolveBrokerPath())
	if err != nil {
		return fmt.Errorf("failed to load brokers: %w", err)
	}

	// Filter brokers
	brokers := brokerDB.Filter(cfg.Options.Regions, cfg.Options.ExcludedBrokers)
	if len(brokers) == 0 {
		fmt.Println("No brokers to process.")
		return nil
	}

	// Initialize template engine
	tmplEngine, err := template.NewEngine()
	if err != nil {
		return fmt.Errorf("failed to initialize templates: %w", err)
	}

	// Initialize email sender (unless dry-run)
	var sender email.Sender
	if !cfg.Options.DryRun {
		sender, err = email.NewSender(cfg.Email)
		if err != nil {
			return fmt.Errorf("failed to initialize email sender: %w", err)
		}
	}

	// Initialize history store
	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to initialize history: %w", err)
	}
	defer store.Close()

	// Process brokers
	if cfg.Options.DryRun {
		fmt.Println("🔍 DRY RUN MODE - No emails will be sent")
		fmt.Println()
	}

	fmt.Printf("📤 Processing %d brokers...\n", len(brokers))
	fmt.Println()

	successCount := 0
	failCount := 0

	for i, b := range brokers {
		fmt.Printf("[%d/%d] %s (%s)\n", i+1, len(brokers), b.Name, b.Email)

		// Render email
		emailMsg, err := tmplEngine.Render(cfg.Options.Template, cfg.Profile, b)
		if err != nil {
			fmt.Printf("  ❌ Failed to render template: %v\n", err)
			failCount++
			continue
		}

		if cfg.Options.DryRun {
			fmt.Printf("  📧 Would send: %s\n", emailMsg.Subject)
			fmt.Printf("  📍 To: %s\n", b.Email)
			successCount++
		} else {
			// Send email
			msg := email.Message{
				To:      b.Email,
				From:    cfg.Email.From,
				Subject: emailMsg.Subject,
				Body:    emailMsg.Body,
			}

			ctx := context.WithValue(context.Background(), "sequence", i)
			result := sender.Send(ctx, msg)

			// Record in history
			record := &history.Record{
				BrokerID:   b.ID,
				BrokerName: b.Name,
				Email:      b.Email,
				Template:   cfg.Options.Template,
				SentAt:     time.Now(),
			}

			if result.Success {
				record.Status = history.StatusSent
				record.MessageID = result.MessageID
				fmt.Printf("  ✅ Sent successfully\n")
				successCount++
			} else {
				record.Status = history.StatusFailed
				record.Error = result.Error.Error()
				fmt.Printf("  ❌ Failed: %v\n", result.Error)
				failCount++
			}

			if err := store.Add(record); err != nil {
				fmt.Printf("  ⚠️  Failed to record history: %v\n", err)
			}

			// Rate limiting
			if i < len(brokers)-1 {
				time.Sleep(time.Duration(cfg.Options.RateLimitMs) * time.Millisecond)
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
	defer store.Close()

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

func runAddBroker() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("➕ Add New Data Broker")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	b := broker.Broker{}

	b.Name = prompt(reader, "Broker name: ")
	b.ID = strings.ToLower(strings.ReplaceAll(b.Name, " ", "-"))
	b.Email = prompt(reader, "Privacy/removal email: ")
	b.Website = prompt(reader, "Website (optional): ")
	b.OptOutURL = prompt(reader, "Opt-out URL (optional): ")
	b.Region = prompt(reader, "Region (us/eu/global): ")
	b.Category = prompt(reader, "Category (people-search/marketing/background-check): ")

	// Load existing brokers
	brokerPath := brokerFile
	if brokerPath == "" {
		brokerPath = "data/brokers.yaml"
	}

	var brokerDB *broker.BrokerDatabase
	if _, err := os.Stat(brokerPath); os.IsNotExist(err) {
		brokerDB = &broker.BrokerDatabase{}
	} else {
		var err error
		brokerDB, err = broker.LoadFromFile(brokerPath)
		if err != nil {
			return fmt.Errorf("failed to load brokers: %w", err)
		}
	}

	if err := brokerDB.Add(b); err != nil {
		return err
	}

	if err := brokerDB.Save(brokerPath); err != nil {
		return fmt.Errorf("failed to save brokers: %w", err)
	}

	fmt.Println()
	fmt.Printf("✅ Added %s to broker database\n", b.Name)

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
	defer store.Close()

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
		server.Shutdown(ctx)
	}()

	return server.Start()
}

func prompt(reader *bufio.Reader, message string) string {
	fmt.Print(message)
	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(input)
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
	defer store.Close()

	// Create inbox monitor
	monitor := inbox.NewMonitor(cfg.Inbox, brokerDB.Brokers)

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
	defer monitor.Disconnect()

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

		// Store in database
		brokerResp := &history.BrokerResponse{
			BrokerID:     email.BrokerID,
			BrokerName:   email.BrokerName,
			ResponseType: string(classified.Type),
			EmailFrom:    email.From,
			EmailSubject: email.Subject,
			FormURL:      classified.FormURL,
			ConfirmURL:   classified.ConfirmURL,
			Confidence:   classified.Confidence,
			NeedsReview:  classified.NeedsReview,
			ReceivedAt:   email.ReceivedAt,
		}

		if err := store.AddBrokerResponse(brokerResp); err != nil {
			fmt.Printf("⚠️  Failed to store response: %v\n", err)
		}

		// Update pipeline status for the broker
		var pipelineStatus history.PipelineStatus
		switch classified.Type {
		case inbox.ResponseSuccess:
			pipelineStatus = history.PipelineConfirmed
		case inbox.ResponseFormRequired:
			pipelineStatus = history.PipelineFormRequired
		case inbox.ResponseConfirmationRequired:
			pipelineStatus = history.PipelineAwaitingConfirmation
		case inbox.ResponseRejected:
			pipelineStatus = history.PipelineRejected
		case inbox.ResponsePending:
			pipelineStatus = history.PipelineAwaitingResponse
		default:
			pipelineStatus = history.PipelineAwaitingResponse
		}

		if err := store.UpdatePipelineStatus(email.BrokerID, pipelineStatus); err != nil {
			// Ignore error if no matching record
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
		} else {
			// Collect UIDs to archive
			var uidsToArchive []uint32
			for _, email := range emails {
				if email.UID > 0 {
					uidsToArchive = append(uidsToArchive, email.UID)
				}
			}

			if len(uidsToArchive) > 0 {
				if err := monitor.ArchiveEmails(uidsToArchive, archiveFolder); err != nil {
					fmt.Printf("⚠️  Could not archive emails: %v\n", err)
				} else {
					fmt.Printf("📁 Archived %d emails to '%s'\n", len(uidsToArchive), archiveFolder)
				}
			}
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

			// Store response
			brokerResp := &history.BrokerResponse{
				BrokerID:     email.BrokerID,
				BrokerName:   email.BrokerName,
				ResponseType: string(classified.Type),
				EmailFrom:    email.From,
				EmailSubject: email.Subject,
				FormURL:      classified.FormURL,
				ConfirmURL:   classified.ConfirmURL,
				Confidence:   classified.Confidence,
				NeedsReview:  classified.NeedsReview,
				ReceivedAt:   email.ReceivedAt,
			}
			store.AddBrokerResponse(brokerResp)
		})

		if err != nil && err != context.Canceled {
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
	default:
		icon = "❓"
	}

	fmt.Printf("%s %s - %s\n", icon, r.Email.BrokerName, r.Type)
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
	defer store.Close()

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
	var brokerID string
	var formURL string
	var headless bool
	var autoSubmit bool
	var screenshotDir string
	var pending bool
	var waitForCaptcha bool

	cmd := &cobra.Command{
		Use:   "fill",
		Short: "Fill opt-out forms using browser automation",
		Long: `Navigate to data broker opt-out forms and automatically fill them using your profile data.

This command uses headless Chrome to:
- Navigate to opt-out form URLs
- Detect and fill form fields with your personal information
- Detect CAPTCHAs (creates tasks for manual solving)
- Optionally submit the form

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
			return runFill(brokerID, formURL, headless, autoSubmit, screenshotDir, pending, waitForCaptcha)
		},
	}

	cmd.Flags().StringVar(&brokerID, "broker", "", "Broker ID to fill form for (uses URL from pipeline)")
	cmd.Flags().StringVar(&formURL, "url", "", "Direct URL to the opt-out form")
	cmd.Flags().BoolVar(&headless, "headless", true, "Run browser in headless mode")
	cmd.Flags().BoolVar(&autoSubmit, "submit", false, "Automatically submit the form after filling")
	cmd.Flags().StringVar(&screenshotDir, "screenshots", "", "Directory to save screenshots (default: ~/.eraser/screenshots)")
	cmd.Flags().BoolVar(&pending, "pending", false, "Fill all pending forms from the pipeline")
	cmd.Flags().BoolVar(&waitForCaptcha, "wait", false, "Wait for user to solve CAPTCHA before continuing (use with --headless=false)")

	return cmd
}

func runFill(brokerID, formURL string, headless, autoSubmit bool, screenshotDir string, pending bool, waitForCaptcha bool) error {
	// Load config for profile data
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Set default screenshot directory
	if screenshotDir == "" {
		home, _ := os.UserHomeDir()
		screenshotDir = filepath.Join(home, ".eraser", "screenshots")
	}

	// Initialize history store
	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to initialize history: %w", err)
	}
	defer store.Close()

	// Create browser config
	browserCfg := browser.DefaultConfig()
	browserCfg.Headless = headless
	browserCfg.ScreenshotDir = screenshotDir
	if cfg.Pipeline.BrowserTimeoutSec > 0 {
		browserCfg.Timeout = time.Duration(cfg.Pipeline.BrowserTimeoutSec) * time.Second
	}

	// Set up wait for CAPTCHA if requested
	if waitForCaptcha {
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

	// Create browser instance
	b, err := browser.New(browserCfg, &cfg.Profile)
	if err != nil {
		return fmt.Errorf("failed to create browser: %w", err)
	}
	defer b.Close()

	fmt.Println("🌐 Browser Automation")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// Determine what to fill
	var formsToFill []struct {
		BrokerID string
		URL      string
	}

	if formURL != "" {
		// Direct URL provided
		formsToFill = append(formsToFill, struct {
			BrokerID string
			URL      string
		}{BrokerID: brokerID, URL: formURL})
	} else if brokerID != "" {
		// Get URL for specific broker from pipeline
		responses, err := store.GetBrokerResponses("form_required", false, 100)
		if err != nil {
			return fmt.Errorf("failed to get broker responses: %w", err)
		}

		found := false
		for _, resp := range responses {
			if resp.BrokerID == brokerID && resp.FormURL != "" {
				formsToFill = append(formsToFill, struct {
					BrokerID string
					URL      string
				}{BrokerID: resp.BrokerID, URL: resp.FormURL})
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("no form URL found for broker: %s", brokerID)
		}
	} else if pending {
		// Get all pending forms
		responses, err := store.GetBrokerResponses("form_required", false, 100)
		if err != nil {
			return fmt.Errorf("failed to get broker responses: %w", err)
		}

		for _, resp := range responses {
			if resp.FormURL != "" {
				formsToFill = append(formsToFill, struct {
					BrokerID string
					URL      string
				}{BrokerID: resp.BrokerID, URL: resp.FormURL})
			}
		}

		if len(formsToFill) == 0 {
			fmt.Println("✅ No pending forms to fill")
			return nil
		}
	} else {
		return fmt.Errorf("please specify --url, --broker, or --pending")
	}

	fmt.Printf("📋 Forms to process: %d\n", len(formsToFill))
	fmt.Println()

	// Process each form
	for i, form := range formsToFill {
		fmt.Printf("[%d/%d] Processing %s\n", i+1, len(formsToFill), form.URL)

		if form.BrokerID != "" {
			fmt.Printf("       Broker: %s\n", form.BrokerID)
		}

		result, err := b.NavigateAndFill(form.URL, form.BrokerID, autoSubmit)
		if err != nil {
			fmt.Printf("       ❌ Error: %v\n", err)
			continue
		}

		// Print result
		if len(result.FieldsFilled) > 0 {
			fmt.Printf("       ✅ Filled fields: %s\n", strings.Join(result.FieldsFilled, ", "))
		}
		if len(result.FieldsMissing) > 0 {
			fmt.Printf("       ⚠️  Missing profile data for: %s\n", strings.Join(result.FieldsMissing, ", "))
		}

		if result.CaptchaFound {
			fmt.Printf("       🤖 CAPTCHA detected: %s\n", result.CaptchaType)

			// Store profile data as JSON for the helper page
			profileData := map[string]string{
				"email":     cfg.Profile.Email,
				"firstName": cfg.Profile.FirstName,
				"lastName":  cfg.Profile.LastName,
				"phone":     cfg.Profile.Phone,
				"address":   cfg.Profile.Address,
				"city":      cfg.Profile.City,
				"state":     cfg.Profile.State,
				"zipCode":   cfg.Profile.ZipCode,
				"country":   cfg.Profile.Country,
			}
			profileJSON, _ := json.Marshal(profileData)

			// Create pending task for CAPTCHA
			task := &history.PendingTask{
				BrokerID:     form.BrokerID,
				BrokerName:   form.BrokerID, // Will need broker lookup for proper name
				TaskType:     history.TaskCaptcha,
				FormURL:      form.URL,
				BrowserState: string(profileJSON), // Store profile data for helper page
				Status:       "pending",
			}
			if result.ScreenshotPath != "" {
				task.ScreenshotPath = result.ScreenshotPath
			}

			if err := store.AddPendingTask(task); err != nil {
				fmt.Printf("       ⚠️  Failed to create task: %v\n", err)
			} else {
				fmt.Printf("       📝 Created CAPTCHA task for manual solving\n")
			}

			// Update pipeline status
			store.UpdatePipelineStatus(form.BrokerID, history.PipelineAwaitingCaptcha)
		} else if result.SubmitAttempted {
			fmt.Printf("       📨 Form submitted!\n")
			store.UpdatePipelineStatus(form.BrokerID, history.PipelineFormFilled)
		} else if result.Success {
			fmt.Printf("       ✅ Form filled (not submitted)\n")
			store.UpdatePipelineStatus(form.BrokerID, history.PipelineFormFilled)
		}

		if result.ScreenshotPath != "" {
			fmt.Printf("       📸 Screenshot: %s\n", result.ScreenshotPath)
		}

		fmt.Println()

		// Small delay between forms to be respectful
		if i < len(formsToFill)-1 {
			time.Sleep(2 * time.Second)
		}
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("✅ Processed %d forms\n", len(formsToFill))

	return nil
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
	defer store.Close()

	// Build list of broker domains for validation
	var brokerDomains []string
	for _, b := range brokerDB.Brokers {
		if b.Website != "" {
			// Extract domain from website
			domain := strings.TrimPrefix(b.Website, "https://")
			domain = strings.TrimPrefix(domain, "http://")
			domain = strings.TrimSuffix(domain, "/")
			if idx := strings.Index(domain, "/"); idx != -1 {
				domain = domain[:idx]
			}
			brokerDomains = append(brokerDomains, domain)

			// Also add the bare domain without www prefix
			if strings.HasPrefix(domain, "www.") {
				brokerDomains = append(brokerDomains, strings.TrimPrefix(domain, "www."))
			}
		}
	}

	// Create confirmation handler
	handler := browser.NewConfirmationHandler(brokerDomains)

	fmt.Println("🔗 Confirmation Link Handler")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	// Determine what to confirm
	var linksToConfirm []struct {
		BrokerID string
		URL      string
	}

	if confirmURL != "" {
		// Direct URL provided
		linksToConfirm = append(linksToConfirm, struct {
			BrokerID string
			URL      string
		}{BrokerID: brokerID, URL: confirmURL})
	} else if brokerID != "" {
		// Get URL for specific broker from pipeline
		responses, err := store.GetBrokerResponses("confirmation_required", false, 100)
		if err != nil {
			return fmt.Errorf("failed to get broker responses: %w", err)
		}

		found := false
		for _, resp := range responses {
			if resp.BrokerID == brokerID && resp.ConfirmURL != "" {
				linksToConfirm = append(linksToConfirm, struct {
					BrokerID string
					URL      string
				}{BrokerID: resp.BrokerID, URL: resp.ConfirmURL})
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("no confirmation URL found for broker: %s", brokerID)
		}
	} else if pending {
		// Get all pending confirmation links
		responses, err := store.GetBrokerResponses("confirmation_required", false, 100)
		if err != nil {
			return fmt.Errorf("failed to get broker responses: %w", err)
		}

		for _, resp := range responses {
			if resp.ConfirmURL != "" {
				linksToConfirm = append(linksToConfirm, struct {
					BrokerID string
					URL      string
				}{BrokerID: resp.BrokerID, URL: resp.ConfirmURL})
			}
		}

		if len(linksToConfirm) == 0 {
			fmt.Println("✅ No pending confirmation links")
			return nil
		}
	} else {
		return fmt.Errorf("please specify --url, --broker, or --pending")
	}

	fmt.Printf("📋 Confirmation links to process: %d\n", len(linksToConfirm))
	if dryRun {
		fmt.Println("🔍 DRY RUN MODE - Links will not be clicked")
	}
	fmt.Println()

	// Process each link
	successCount := 0
	failCount := 0

	for i, link := range linksToConfirm {
		fmt.Printf("[%d/%d] Processing confirmation link\n", i+1, len(linksToConfirm))
		if link.BrokerID != "" {
			fmt.Printf("       Broker: %s\n", link.BrokerID)
		}
		fmt.Printf("       URL: %s\n", truncateURL(link.URL, 60))

		// Validate domain if requested
		if validateDomain {
			valid, domain, err := handler.ValidateDomain(link.URL)
			if err != nil {
				fmt.Printf("       ❌ Invalid URL: %v\n", err)
				failCount++
				continue
			}
			if !valid {
				fmt.Printf("       ⚠️  Domain %s is not a known broker domain\n", domain)
				fmt.Printf("       Use --validate-domain=false to override\n")
				failCount++
				continue
			}
			fmt.Printf("       ✓ Domain validated: %s\n", domain)
		}

		if dryRun {
			fmt.Printf("       📋 Would click this link (dry run)\n")
			successCount++
			fmt.Println()
			continue
		}

		// Click the confirmation link
		result, err := handler.ClickConfirmationLink(link.URL, false) // Domain already validated above
		if err != nil {
			fmt.Printf("       ❌ Error: %v\n", err)
			failCount++
			continue
		}

		// Show result
		fmt.Printf("       HTTP Status: %d\n", result.StatusCode)
		if len(result.RedirectPath) > 1 {
			fmt.Printf("       Redirects: %d hops\n", len(result.RedirectPath)-1)
		}
		if result.FinalURL != link.URL {
			fmt.Printf("       Final URL: %s\n", truncateURL(result.FinalURL, 60))
		}

		// Extract and show status
		status := handler.ExtractConfirmationStatus(result)
		if result.Success {
			fmt.Printf("       ✅ %s\n", status)
			successCount++

			// Update pipeline status
			if link.BrokerID != "" {
				store.UpdatePipelineStatus(link.BrokerID, history.PipelineConfirmed)
			}
		} else {
			fmt.Printf("       ⚠️  %s\n", status)
			failCount++

			// Still update status to indicate we tried
			if link.BrokerID != "" {
				store.UpdatePipelineStatus(link.BrokerID, history.PipelineFailed)
			}
		}

		fmt.Println()

		// Small delay between confirmations
		if i < len(linksToConfirm)-1 {
			time.Sleep(1 * time.Second)
		}
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if dryRun {
		fmt.Printf("📊 Dry run complete: %d links would be clicked\n", len(linksToConfirm))
	} else {
		fmt.Printf("📊 Complete: %d confirmed, %d failed\n", successCount, failCount)
	}

	return nil
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

	// Create inbox monitor
	monitor := inbox.NewMonitor(cfg.Inbox, brokerDB.Brokers)

	// Connect
	ctx := context.Background()
	if err := monitor.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to inbox: %w", err)
	}
	defer monitor.Disconnect()

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
		// Extract the bounced recipient
		bouncedRecipient := inbox.ExtractBouncedRecipient(&email)
		if bouncedRecipient == "" {
			fmt.Printf("⚠️  Could not extract bounced address from: %s\n", email.Subject)
			continue
		}

		// Find the broker
		b := brokerDB.FindByEmail(bouncedRecipient)
		if b == nil {
			fmt.Printf("⚠️  %s - not found in broker database\n", bouncedRecipient)
			continue
		}

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

	// Remove the brokers
	fmt.Printf("\n🗑️  Removing %d broker(s) from database...\n\n", len(bouncedBrokers))

	removed := 0
	for _, bb := range bouncedBrokers {
		if brokerDB.RemoveByEmail(bb.email) != nil {
			fmt.Printf("✓ Removed %s (%s)\n", bb.broker.Name, bb.email)
			removed++
		}
	}

	// Save with backup
	if err := brokerDB.SaveWithBackup(brokerPath); err != nil {
		return fmt.Errorf("failed to save broker database: %w", err)
	}

	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("✓ Removed %d broker(s) with invalid email addresses\n", removed)
	fmt.Printf("  Backup saved to: %s.bak\n", brokerPath)

	return nil
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
