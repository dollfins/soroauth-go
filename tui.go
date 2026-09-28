// Build constraint: everything below depends on bubbletea, which does not
// compile for js/wasm. The signing core must build for the browser (issue #52),
// so the interactive TUI -- a terminal feature with no browser meaning -- is
// excluded from that target rather than dragging a terminal UI library into it.
// The CLI, which is never built for js/wasm, still has it.
//go:build !js && !wasm

package soroauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// TUIModel holds the state for the interactive TUI.
type TUIModel struct {
	// Entry being inspected/signed
	entry *xdr.SorobanAuthorizationEntry

	// Inspection result
	info *EntryInfo

	// Findings from risk analysis
	findings []Finding

	// Config
	validUntilLedger  uint32
	networkPassphrase string
	secretEnvVar      string
	forAddress        string

	// UI state
	stage        int // 0=inspect, 1=sign, 2=done
	cursor       int
	selectedNode string
	width        int
	height       int
	err          error
	quitting     bool
	done         bool

	// Signing state
	signer      Signer
	signedEntry *xdr.SorobanAuthorizationEntry

	// Styles
	styles *TUIStyles
}

// TUIStyles holds the lipgloss styles for the TUI.
type TUIStyles struct {
	base            lipgloss.Style
	header          lipgloss.Style
	section         lipgloss.Style
	item            lipgloss.Style
	selectedItem    lipgloss.Style
	findingCritical lipgloss.Style
	findingWarning  lipgloss.Style
	findingInfo     lipgloss.Style
	help            lipgloss.Style
	success         lipgloss.Style
	error           lipgloss.Style
}

// NewTUIStyles creates the default styles.
func NewTUIStyles() *TUIStyles {
	return &TUIStyles{
		base: lipgloss.NewStyle().
			Padding(1, 2),
		header: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			MarginBottom(1),
		section: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("86")).
			MarginTop(1).
			MarginBottom(1),
		item: lipgloss.NewStyle().
			PaddingLeft(2),
		selectedItem: lipgloss.NewStyle().
			PaddingLeft(2).
			Foreground(lipgloss.Color("205")).
			Bold(true),
		findingCritical: lipgloss.NewStyle().
			PaddingLeft(2).
			Foreground(lipgloss.Color("196")).
			Bold(true),
		findingWarning: lipgloss.NewStyle().
			PaddingLeft(2).
			Foreground(lipgloss.Color("214")),
		findingInfo: lipgloss.NewStyle().
			PaddingLeft(2).
			Foreground(lipgloss.Color("86")),
		help: lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			MarginTop(1),
		success: lipgloss.NewStyle().
			Foreground(lipgloss.Color("46")).
			Bold(true),
		error: lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true),
	}
}

// TUI runs the interactive TUI for inspecting and signing an authorization entry.
//
// It reads the entry from base64 stdin (or --entry flag), and the secret seed
// from the environment variable named by secretEnvVar (or --secret-env flag).
// The seed is never prompted for or echoed.
//
// If stdin is not a TTY, it degrades to non-interactive output (equivalent to
// running inspect and sign commands).
func TUI(ctx context.Context, entryB64 string, validUntilLedger uint32, networkPassphrase string, secretEnvVar string, forAddress string) error {
	// Decode entry
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(entryB64, &entry); err != nil {
		return fmt.Errorf("unmarshalling entry: %w", err)
	}

	// Inspect entry
	info, err := Inspect(entry)
	if err != nil {
		return fmt.Errorf("inspecting entry: %w", err)
	}

	// Analyze for findings
	findings, err := Analyze(entry, nil)
	if err != nil {
		return fmt.Errorf("analyzing entry: %w", err)
	}

	// If not a TTY, fall back to non-interactive output
	if !isTTY() {
		return runNonInteractive(ctx, &entry, &info, findings, validUntilLedger, networkPassphrase, secretEnvVar, forAddress)
	}

	// Get secret from environment
	seed := os.Getenv(secretEnvVar)
	if seed == "" {
		return fmt.Errorf("environment variable %q not set", secretEnvVar)
	}

	kp, err := keypair.ParseFull(seed)
	if err != nil {
		return fmt.Errorf("parsing secret seed: %w", err)
	}

	signer := NewEd25519Signer(kp)

	model := &TUIModel{
		entry:             &entry,
		info:              &info,
		findings:          findings,
		validUntilLedger:  validUntilLedger,
		networkPassphrase: networkPassphrase,
		secretEnvVar:      secretEnvVar,
		forAddress:        forAddress,
		signer:            signer,
		styles:            NewTUIStyles(),
	}

	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err = p.Run()
	return err
}

// isTTY checks if stdin is a terminal.
func isTTY() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// runNonInteractive runs the inspect and sign flow without TUI.
func runNonInteractive(ctx context.Context, entry *xdr.SorobanAuthorizationEntry, info *EntryInfo, findings []Finding, validUntilLedger uint32, networkPassphrase string, secretEnvVar string, forAddress string) error {
	// Print inspection
	fmt.Println("=== Authorization Entry Inspection ===")
	printEntryInfo(info)

	// Print findings
	if len(findings) > 0 {
		fmt.Println("\n=== Risk Findings ===")
		for _, f := range findings {
			printFinding(f)
		}
	} else {
		fmt.Println("\n=== Risk Findings ===")
		fmt.Println("  No findings")
	}

	// Sign
	seed := os.Getenv(secretEnvVar)
	if seed == "" {
		return fmt.Errorf("environment variable %q not set", secretEnvVar)
	}
	kp, err := keypair.ParseFull(seed)
	if err != nil {
		return fmt.Errorf("parsing secret seed: %w", err)
	}
	signer := NewEd25519Signer(kp)

	opts := []AuthorizeOption{}
	if forAddress != "" {
		opts = append(opts, ForAddress(forAddress))
	}

	signed, err := AuthorizeEntry(ctx, *entry, signer, validUntilLedger, networkPassphrase, opts...)
	if err != nil {
		return fmt.Errorf("signing entry: %w", err)
	}

	// Output signed entry as base64
	signedBytes, err := signed.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshalling signed entry: %w", err)
	}
	fmt.Println("\n=== Signed Entry (base64) ===")
	fmt.Println(base64.StdEncoding.EncodeToString(signedBytes))

	return nil
}

func printEntryInfo(info *EntryInfo) {
	fmt.Printf("Credential Type: %s\n", info.CredentialType)
	fmt.Printf("Address Bound: %v\n", info.AddressBound)
	if info.Address != "" {
		fmt.Printf("Address: %s\n", info.Address)
	}
	if info.Nonce != 0 {
		fmt.Printf("Nonce: %d\n", info.Nonce)
	}
	if info.ValidUntilLedger != 0 {
		fmt.Printf("Valid Until Ledger: %d\n", info.ValidUntilLedger)
	}
	fmt.Printf("Top Level Signed: %v\n", info.TopLevelSigned)
	if info.RootContract != "" {
		fmt.Printf("Root Contract: %s\n", info.RootContract)
	}
	if info.RootFunction != "" {
		fmt.Printf("Root Function: %s\n", info.RootFunction)
	}
	fmt.Printf("Sub Invocations: %d\n", info.SubInvocations)

	if len(info.Delegates) > 0 {
		fmt.Println("\nDelegates:")
		printDelegates(info.Delegates, 1)
	}
}

func printDelegates(delegates []NodeInfo, depth int) {
	indent := strings.Repeat("  ", depth)
	for _, d := range delegates {
		signedMark := " "
		if d.Signed {
			signedMark = "✓"
		}
		fmt.Printf("%s[%s] %s\n", indent, signedMark, d.Address)
		if len(d.Nested) > 0 {
			printDelegates(d.Nested, depth+1)
		}
	}
}

func printFinding(f Finding) {
	var prefix string
	switch f.Severity {
	case SeverityCritical:
		prefix = "CRITICAL"
	case SeverityWarning:
		prefix = "WARNING"
	case SeverityInfo:
		prefix = "INFO"
	}
	fmt.Printf("  [%s] %s: %s\n", prefix, f.Code, f.Title)
	fmt.Printf("      %s\n", f.Description)
	fmt.Printf("      Rationale: %s\n", f.Rationale)
}

// Init initializes the TUI model.
func (m *TUIModel) Init() tea.Cmd {
	return nil
}

// Update handles messages and updates the model.
func (m *TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		case "enter":
			return m.handleEnter()
		case "up", "k":
			m.moveCursor(-1)
			return m, nil
		case "down", "j":
			m.moveCursor(1)
			return m, nil
		case "s":
			if m.stage == 0 {
				return m.startSigning()
			}
		}
	}

	return m, nil
}

func (m *TUIModel) handleEnter() (*TUIModel, tea.Cmd) {
	if m.stage == 0 && m.cursor < len(m.getInspectItems()) {
		m.selectedNode = m.getInspectItems()[m.cursor]
		m.stage = 1 // Show node detail
		return m, nil
	}
	if m.stage == 1 {
		m.stage = 0
		m.selectedNode = ""
		return m, nil
	}
	return m, nil
}

func (m *TUIModel) moveCursor(delta int) {
	items := m.getInspectItems()
	if len(items) == 0 {
		return
	}
	m.cursor += delta
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor >= len(items) {
		m.cursor = len(items) - 1
	}
}

func (m *TUIModel) startSigning() (*TUIModel, tea.Cmd) {
	m.stage = 2
	go func() {
		opts := []AuthorizeOption{}
		if m.forAddress != "" {
			opts = append(opts, ForAddress(m.forAddress))
		}
		signed, err := AuthorizeEntry(context.Background(), *m.entry, m.signer, m.validUntilLedger, m.networkPassphrase, opts...)
		if err != nil {
			m.err = err
		} else {
			m.signedEntry = &signed
		}
		m.done = true
	}()
	return m, nil
}

func (m *TUIModel) getInspectItems() []string {
	var items []string
	items = append(items, fmt.Sprintf("Credential Type: %s", m.info.CredentialType))
	items = append(items, fmt.Sprintf("Address Bound: %v", m.info.AddressBound))
	if m.info.Address != "" {
		items = append(items, fmt.Sprintf("Address: %s", m.info.Address))
	}
	if m.info.Nonce != 0 {
		items = append(items, fmt.Sprintf("Nonce: %d", m.info.Nonce))
	}
	if m.info.ValidUntilLedger != 0 {
		items = append(items, fmt.Sprintf("Valid Until Ledger: %d", m.info.ValidUntilLedger))
	}
	items = append(items, fmt.Sprintf("Top Level Signed: %v", m.info.TopLevelSigned))
	if m.info.RootContract != "" {
		items = append(items, fmt.Sprintf("Root Contract: %s", m.info.RootContract))
	}
	if m.info.RootFunction != "" {
		items = append(items, fmt.Sprintf("Root Function: %s", m.info.RootFunction))
	}
	items = append(items, fmt.Sprintf("Sub Invocations: %d", m.info.SubInvocations))

	if len(m.info.Delegates) > 0 {
		items = append(items, "--- Delegates ---")
		items = append(items, m.formatDelegates(m.info.Delegates, 1)...)
	}

	if len(m.findings) > 0 {
		items = append(items, "--- Risk Findings ---")
		for _, f := range m.findings {
			items = append(items, fmt.Sprintf("[%s] %s: %s", f.Severity, f.Code, f.Title))
		}
	} else {
		items = append(items, "--- Risk Findings ---")
		items = append(items, "No findings")
	}

	return items
}

func (m *TUIModel) formatDelegates(delegates []NodeInfo, depth int) []string {
	var items []string
	indent := strings.Repeat("  ", depth)
	for _, d := range delegates {
		signedMark := " "
		if d.Signed {
			signedMark = "✓"
		}
		items = append(items, fmt.Sprintf("%s[%s] %s", indent, signedMark, d.Address))
		if len(d.Nested) > 0 {
			items = append(items, m.formatDelegates(d.Nested, depth+1)...)
		}
	}
	return items
}

// View renders the TUI.
func (m *TUIModel) View() string {
	if m.quitting {
		return ""
	}

	if m.done {
		return m.viewDone()
	}

	if m.err != nil {
		return m.styles.error.Render("Error: "+m.err.Error()) + "\n\nPress q to quit"
	}

	switch m.stage {
	case 0:
		return m.viewInspect()
	case 1:
		return m.viewNodeDetail()
	case 2:
		return m.viewSigning()
	}
	return ""
}

func (m *TUIModel) viewInspect() string {
	var b strings.Builder

	b.WriteString(m.styles.header.Render("soroauth - Authorization Entry Inspector"))
	b.WriteString("\n\n")

	items := m.getInspectItems()
	for i, item := range items {
		style := m.styles.item
		if i == m.cursor {
			style = m.styles.selectedItem
		}
		b.WriteString(style.Render(item))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(m.styles.help.Render("↑/↓: navigate  Enter: detail  s: sign  q: quit"))
	return m.styles.base.Render(b.String())
}

func (m *TUIModel) viewNodeDetail() string {
	var b strings.Builder

	b.WriteString(m.styles.header.Render("Node Detail: " + m.selectedNode))
	b.WriteString("\n\n")

	b.WriteString(m.styles.help.Render("Enter: back  q: quit"))
	return m.styles.base.Render(b.String())
}

func (m *TUIModel) viewSigning() string {
	var b strings.Builder

	b.WriteString(m.styles.header.Render("Signing..."))
	b.WriteString("\n\n")

	b.WriteString("Signing entry with key from environment...")
	b.WriteString("\n\n")

	if m.done {
		if m.err != nil {
			b.WriteString(m.styles.error.Render("Signing failed: " + m.err.Error()))
		} else {
			b.WriteString(m.styles.success.Render("Entry signed successfully!"))
			signedBytes, _ := m.signedEntry.MarshalBinary()
			b.WriteString("\n\nSigned entry (base64):\n")
			b.WriteString(base64.StdEncoding.EncodeToString(signedBytes))
		}
	}

	b.WriteString("\n\n")
	b.WriteString(m.styles.help.Render("q: quit"))
	return m.styles.base.Render(b.String())
}

func (m *TUIModel) viewDone() string {
	var b strings.Builder

	if m.err != nil {
		b.WriteString(m.styles.error.Render("Error: " + m.err.Error()))
	} else {
		b.WriteString(m.styles.success.Render("Done!"))
		if m.signedEntry != nil {
			signedBytes, _ := m.signedEntry.MarshalBinary()
			b.WriteString("\n\nSigned entry (base64):\n")
			b.WriteString(base64.StdEncoding.EncodeToString(signedBytes))
		}
	}

	b.WriteString("\n\n")
	b.WriteString(m.styles.help.Render("q: quit"))
	return m.styles.base.Render(b.String())
}

// TUICommand adds the tui subcommand to the CLI.
func TUICommand(args []string) error {
	if len(args) < 5 {
		return fmt.Errorf("usage: tui --entry <base64> --valid-until <ledger> --network <passphrase> --secret-env <var> [--for <addr>]")
	}

	var entryB64 string
	var validUntilLedger uint32
	var networkPassphrase string
	var secretEnvVar string
	var forAddress string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--entry":
			if i+1 < len(args) {
				entryB64 = args[i+1]
				i++
			}
		case "--valid-until":
			if i+1 < len(args) {
				// A malformed value leaves validUntilLedger at zero, which the
				// required-flag check below refuses; the TUI parses its own
				// flags, so there is no parse error to surface here.
				_, _ = fmt.Sscanf(args[i+1], "%d", &validUntilLedger)
				i++
			}
		case "--network":
			if i+1 < len(args) {
				networkPassphrase = args[i+1]
				i++
			}
		case "--secret-env":
			if i+1 < len(args) {
				secretEnvVar = args[i+1]
				i++
			}
		case "--for":
			if i+1 < len(args) {
				forAddress = args[i+1]
				i++
			}
		}
	}

	if entryB64 == "" || validUntilLedger == 0 || networkPassphrase == "" || secretEnvVar == "" {
		return fmt.Errorf("missing required flags")
	}

	// Resolve network passphrase
	switch networkPassphrase {
	case "testnet":
		networkPassphrase = network.TestNetworkPassphrase
	case "public":
		networkPassphrase = network.PublicNetworkPassphrase
	}

	return TUI(context.Background(), entryB64, validUntilLedger, networkPassphrase, secretEnvVar, forAddress)
}
