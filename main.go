package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Define a simple color palette
var (
	colorAccent  = lipgloss.Color("#88C0D0") // Cyan for connection names/highlights
	colorError   = lipgloss.Color("#BF616A") // Red for errors
	colorSubtle  = lipgloss.Color("#4C566A") // Dark gray for status background
	colorPrimary = lipgloss.Color("#D8DEE9") // Light gray/white for text
)

// Define the core styles
var (
	// Style for displaying errors
	errorStyle = lipgloss.NewStyle().
			Foreground(colorError).
			Background(lipgloss.Color("#2E3440")). // Dark background for contrast
			Padding(0, 1)

	// Style for the bottom status bar
	statusStyle = lipgloss.NewStyle().
			Foreground(colorPrimary).
			Background(colorSubtle).
			Padding(0, 1)

	// Style for the active shell view area (optional border/padding)
	shellAreaStyle = lipgloss.NewStyle().
			Padding(0, 1)
)

// connectionsFilePath is the name of our file where we'll store connections.
const connectionsFilePath = "connections.json"

// Connection represents a single SSH connection profile.
// The `json` tags tell the `json` package how to encode and decode the fields.
type Connection struct {
	Name string `json:"name"`
	User string `json:"user"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// loadConnections reads connections from the JSON file and returns a slice of Connection structs.
func loadConnections() ([]Connection, error) {
	file, err := os.ReadFile(connectionsFilePath)
	if err != nil {
		// If the file doesn't exist, that's okay, we'll just start with an empty list.
		if os.IsNotExist(err) {
			return []Connection{}, nil
		}
		return nil, fmt.Errorf("could not read connections file: %w", err)
	}

	var connections []Connection
	if err := json.Unmarshal(file, &connections); err != nil {
		return nil, fmt.Errorf("could not unmarshal connections data: %w", err)
	}

	return connections, nil
}

// saveConnections writes the provided slice of Connection structs to the JSON file.
func saveConnections(connections []Connection) error {
	data, err := json.MarshalIndent(connections, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal connections data: %w", err)
	}

	if err := os.WriteFile(connectionsFilePath, data, 0o644); err != nil {
		return fmt.Errorf("could not write connections file: %w", err)
	}

	return nil
}

// deleteConnection removes a connection by name and saves the updated list.
func deleteConnection(connections []Connection, name string) ([]Connection, error) {
	var updatedConnections []Connection
	for _, conn := range connections {
		if conn.Name != name {
			updatedConnections = append(updatedConnections, conn)
		}
	}
	if err := saveConnections(updatedConnections); err != nil {
		return nil, err
	}
	return updatedConnections, nil
}

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

// --- TUI-specific code starts here ---

// item is a struct that satisfies the list.Item interface.
// This is necessary for Bubble Tea's list component to work.
type item struct {
	title       string
	description string
	connection  *Connection
}

// These methods satisfy the list.Item interface.
func (i item) FilterValue() string { return i.title }
func (i item) Title() string       { return i.title }
func (i item) Description() string { return i.description }

// a custom message type to indicate that a new connection was saved
type (
	connectionSavedMsg Connection
	// connectionsLoadedMsg is a custom message type to carry our loaded connections.
	connectionsLoadedMsg []Connection
	// state machine for our application views
	state int
	// sshConnectedMsg is returned when the ssh client is successfully created.
	sshConnectedMsg *ssh.Client
	// sshClientErrorMsg is returned if the connection fails.
	sshClientErrorMsg error
	// data received from the remote shell
	shellOutputMsg []byte
	// session closed or error
	shellExitMsg struct{ Err error }

	connectionDeletedMsg struct{ name string }
)

const (
	listView state = iota
	formView
	passwordPromptView
	connectingView
	shellView
)

// model is the main application state.
// It holds our list of connections and the list component itself.
type model struct {
	connections       []Connection
	list              list.Model
	inputs            []textinput.Model
	passwordInput     textinput.Model
	state             state
	focusIndex        int
	currentConnection *Connection
	shellOutput       string
	err               error
	sshClient         *ssh.Client
	sshSession        *ssh.Session
	sshStdin          io.WriteCloser
	sshStdinBuf       *bufio.Writer
	sshStdout         io.Reader
	termWidth         int
	termHeight        int
}

type shellReadyMsg struct {
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
}

// getHostKeyCallback is a security helper to load keys from the startdard known_hosts file.
func getHostKeyCallback() (ssh.HostKeyCallback, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("could not get current user home directory: %w", err)
	}
	knownHostsPath := fmt.Sprintf("%s/.ssh/known_hosts", usr.HomeDir)

	// knownhosts.New handles reading teh file and creating the callback function.
	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		// this can fail if the file doesn't exist or is inaccessible.
		return nil, fmt.Errorf("could not load known_hosts file from %s: %w", knownHostsPath, err)
	}
	return hostKeyCallback, nil
}

// is the command that attempts to dial and auth the ssh connection.
func connectToSSH(conn Connection, password string) tea.Cmd {
	return func() tea.Msg {
		hostKeyCallback, err := getHostKeyCallback()
		if err != nil {
			return sshClientErrorMsg(fmt.Errorf("security steup error: %w", err))
		}

		config := &ssh.ClientConfig{
			User: conn.User,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			// use the secure callback.
			HostKeyCallback: hostKeyCallback,
			Timeout:         5 * time.Second,
		}

		addr := fmt.Sprintf("%s:%d", conn.Host, conn.Port)
		client, err := ssh.Dial("tcp", addr, config)
		if err != nil {
			// this is where common host key errors will appear.
			return sshClientErrorMsg(fmt.Errorf("failed to dial or key mismatch: %w", err))
		}
		return sshConnectedMsg(client)
	}
}

// loadConnectionsCmd is a command that loads our connections asynchronously.
func loadConnectionsCmd() tea.Msg {
	connections, err := loadConnections()
	if err != nil {
		fmt.Printf("Error loading connections: %v\n", err)
		os.Exit(1)
	}
	return connectionsLoadedMsg(connections)
}

// InitialModel returns the starting state of our TUI application.
func InitialModel() model {
	// We create a new list component.
	l := list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0)
	l.Title = "SSH Connection Manager (press 'a' to add or 'd' to delete connections)"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	// create the text inputs for the formView
	inputs := make([]textinput.Model, 4)
	var t textinput.Model
	for i := range inputs {
		t = textinput.New()
		t.Cursor.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
		t.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

		switch i {
		case 0:
			t.Placeholder = "Name"
			t.Focus()
		case 1:
			t.Placeholder = "User"
		case 2:
			t.Placeholder = "Host"
		case 3:
			t.Placeholder = "Port"
		}
		inputs[i] = t
	}

	pInput := textinput.New()
	pInput.EchoMode = textinput.EchoPassword
	pInput.EchoCharacter = '*'
	pInput.Placeholder = "SSH Password"

	return model{
		list:          l,
		inputs:        inputs,
		passwordInput: pInput,
		state:         listView,
		focusIndex:    0,
	}
}

// Init is the starting point for our program.
// It returns a command to perform a side effect, like loading data.
func (m model) Init() tea.Cmd {
	return loadConnectionsCmd
}

// Update handles all user input and messages.
// It receives messages and returns an updated model and optional commands.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// When the window resizes, we adjust the list component's dimensions.
		m.list.SetWidth(msg.Width)
		m.list.SetHeight(msg.Height - 1)

		m.termWidth = msg.Width
		m.termHeight = msg.Height
		return m, nil

	case connectionsLoadedMsg:
		// This custom message is sent when our `loadConnectionsCmd` completes.
		// We update our model's connections and populate the list.
		m.connections = msg
		items := make([]list.Item, len(m.connections))
		for i, conn := range m.connections {
			items[i] = item{
				title:       conn.Name,
				description: fmt.Sprintf("%s@%s:%d", conn.User, conn.Host, conn.Port),
				connection:  &conn,
			}
		}
		m.list.SetItems(items)
		return m, nil
	case connectionSavedMsg:
		// when a connection is saved, we add it to our list and switch back to the list view.
		m.connections = append(m.connections, Connection(msg))
		items := make([]list.Item, len(m.connections))
		for i, conn := range m.connections {
			items[i] = item{
				title:       conn.Name,
				description: fmt.Sprintf("%s@%s:%d", conn.User, conn.Host, conn.Port),
				connection:  &conn,
			}
		}
		m.list.SetItems(items)
		m.state = listView
		m.focusIndex = 0
		return m, nil

	case connectionDeletedMsg:
		return m, loadConnectionsCmd

	case sshConnectedMsg:
		m.state = connectingView
		m.sshClient = msg

		return m, startShellCmd(m.sshClient, m.currentConnection, m.termWidth, m.termHeight)

	case shellReadyMsg: // catch the new return type from startShellCmd
		m.state = shellView
		m.sshSession = msg.session
		m.sshStdin = msg.stdin
		m.sshStdout = msg.stdout
		m.sshStdinBuf = bufio.NewWriter(m.sshStdin)
		m.shellOutput = "" // clear the success message

		// now return the session is ready, start the continuous read loop.
		return m, readShellCmd(m.sshStdout)

	case shellOutputMsg:
		// append new data to the output buffer and keep the read loop running
		m.shellOutput += string(msg)
		// important: the key to the continuous loop is returning the read command here.
		return m, readShellCmd(m.sshStdout)

	case shellExitMsg:
		// shell closed, clean up and go back to list.
		m.state = listView
		m.err = msg.Err // display exit reason
		if m.sshClient != nil {
			m.sshClient.Close()
		}
		if m.sshSession != nil {
			m.sshSession.Close()
		}
		m.sshClient = nil
		m.sshSession = nil
		m.currentConnection = nil
		return m, tea.Quit

	case sshClientErrorMsg:
		m.state = listView
		m.err = msg
		return m, nil
	}

	// global key handler while in shell view.
	if m.state == shellView {
		if k, ok := msg.(tea.KeyMsg); ok {
			// handle CTRL+Q to explicitely disconnect.
			if k.String() == "ctrl+q" || k.String() == "ctrl+c" {
				// send exit message to close the session gracefully.
				m.sshSession.Close()
				return m, tea.Quit
			}

			// send all other key presses to the remote shell's stdin.
			if m.sshSession != nil && m.sshStdin != nil {
				// write the eawy bytes of the key press to the remote session.
				// for runes, we need to handle special cases like 'enter'.
				var inputBytes []byte

				// Check for specific control/special keys
				switch k.Type {
				case tea.KeyEnter:
					inputBytes = []byte{'\r'}

				case tea.KeyBackspace:
					// *** FIX: Send the standard delete character (ASCII 127) ***
					inputBytes = []byte{127}

				case tea.KeyUp:
					// *** FIX: Send ANSI Up Arrow sequence ***
					inputBytes = []byte{27, 91, 65} // ESC [ A

				case tea.KeyDown:
					// *** FIX: Send ANSI Down Arrow sequence ***
					inputBytes = []byte{27, 91, 66} // ESC [ B

				case tea.KeyRight:
					// *** FIX: Send ANSI Right Arrow sequence ***
					inputBytes = []byte{27, 91, 67} // ESC [ C

				case tea.KeyLeft:
					// *** FIX: Send ANSI Left Arrow sequence ***
					inputBytes = []byte{27, 91, 68} // ESC [ D

				case tea.KeyRunes:
					inputBytes = []byte(string(k.Runes))

				case tea.KeyTab:
					inputBytes = []byte{'\t'}

				default:
					// Catch all other keys (like F-keys, Ctrl+L, etc.)
					if len(k.String()) > 0 {
						inputBytes = []byte(k.String())
					}
				}

				if len(inputBytes) > 0 {
					if _, err := m.sshStdinBuf.Write(inputBytes); err != nil {
						return m, sendMsgCmd(shellExitMsg{Err: fmt.Errorf("failed to write to shell: %w", err)})
					}

					if err := m.sshStdinBuf.Flush(); err != nil {
						return m, sendMsgCmd(shellExitMsg{Err: fmt.Errorf("failed to flush input: %w", err)})
					}
				}
			}
		}
		return m, nil
	}

	switch m.state {
	case listView:
		return m.updateList(msg)
	case formView:
		return m.updateForm(msg)
	case passwordPromptView:
		return m.updatePasswordPrompt(msg)
	}

	return m, nil
}

func (m model) updateList(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Check for global key presses.
		switch msg.String() {
		case "a":
			// switch to the form views
			m.state = formView
			m.focusIndex = 0
			// reset form inputs for new entry
			for i := range m.inputs {
				m.inputs[i].SetValue("")
			}
			m.inputs[m.focusIndex].Focus()
			return m, nil

		case "q", "ctrl+c":
			return m, tea.Quit

		case "enter":
			// Corrected from `selectedItem` to `SelectedItem`.
			if len(m.list.Items()) > 0 {
				selectedItem := m.list.SelectedItem().(item)
				m.currentConnection = selectedItem.connection
				m.state = passwordPromptView
				m.passwordInput.Focus()
				m.passwordInput.SetValue("")
				return m, nil
			}

		case "d":
			if len(m.list.Items()) > 0 {
				// get the selected connectin's name.
				selectedItem := m.list.SelectedItem().(item)
				connName := selectedItem.connection.Name

				// execute the deletion command.
				return m, func() tea.Msg {
					_, err := deleteConnection(m.connections, connName)
					if err != nil {
						return tea.Quit
					}
					return connectionDeletedMsg{name: connName}
				}
			}
			return m, nil
		}
	}
	// Pass any other messages (like navigation keys) to the list component.
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// updateForm handles updates for the form view
func (m model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	// placeholder
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.state = listView
			return m, nil
		case "enter":
			// save the new connection and switch back to list view
			port, err := strconv.Atoi(m.inputs[3].Value())
			if err != nil {
				port = 22 // default to port 22 if invalid.
			}

			newConn := Connection{
				Name: m.inputs[0].Value(),
				User: m.inputs[1].Value(),
				Host: m.inputs[2].Value(),
				Port: port,
			}
			// sace the new connection asynchronously.
			return m, func() tea.Msg {
				m.connections = append(m.connections, newConn)
				err := saveConnections(m.connections)
				if err != nil {
					return tea.Quit
				}
				return connectionSavedMsg(newConn)
			}
		case "tab", "shift-tab", "down", "up":
			s := msg.String()
			if s == "up" || s == "shift+tab" {
				m.focusIndex--
			} else {
				m.focusIndex++
			}
			// wrap the focus index.
			if m.focusIndex < 0 {
				m.focusIndex = len(m.inputs) - 1
			} else if m.focusIndex >= len(m.inputs) {
				m.focusIndex = 0
			}

			// blur all inputs.
			for i := range m.inputs {
				m.inputs[i].Blur()
			}

			// focus the current input.
			m.inputs[m.focusIndex].Focus()
		}
	}

	var cmd tea.Cmd
	m.inputs[m.focusIndex], cmd = m.inputs[m.focusIndex].Update(msg)
	return m, cmd
}

func (m model) updatePasswordPrompt(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.state = listView
			m.passwordInput.Blur()
			return m, nil
		case "enter":
			password := m.passwordInput.Value()
			m.passwordInput.Blur()

			m.state = connectingView
			return m, connectToSSH(*m.currentConnection, password)
		}
	}

	m.passwordInput, cmd = m.passwordInput.Update(msg)
	return m, cmd
}

func (m model) View() string {
	var s string
	if m.err != nil {
		// we clear the error so it doesn't persist across successfull interactions
		s = errorStyle.Render(fmt.Sprintf("ERROR: %v\n", m.err))
		m.err = nil
	}

	switch m.state {
	case listView:
		s += m.list.View()
	case formView:
		var b strings.Builder
		b.WriteString("Add a New Connection\n\n")

		for i, input := range m.inputs {
			b.WriteString(input.View())
			if i < len(m.inputs)-1 {
				b.WriteString("\n")
			}
		}
		b.WriteString("\n\nPress Enter to save, Esc to go back.")
		s += b.String()
	case passwordPromptView:
		var b strings.Builder
		b.WriteString(fmt.Sprintf("Enter password for %s@%s: \n\n", m.currentConnection.User, m.currentConnection.Host))
		b.WriteString(m.passwordInput.View())
		b.WriteString("\n\nPress Enter to connect, Esc to cancel.")
		s += b.String()
	case connectingView:
		s += fmt.Sprintf("Connecting to %s@%s:%d...", m.currentConnection.User, m.currentConnection.Host, m.currentConnection.Port)
	case shellView:
		// 1. Build the status text
		statusText := fmt.Sprintf("CONNECTED: %s@%s:%d",
			m.currentConnection.User,
			m.currentConnection.Host,
			m.currentConnection.Port)

		// 2. Render the status text using statusStyle
		statusBar := statusStyle.
			Width(m.termWidth). // Use stored width
			Render(statusText)

		// 3. Append to the final output with a newline separation
		s += statusBar + "\n"

		// The main shell content must be rendered beneath the status bar.
		renderedShell := shellAreaStyle.
			// Height is CRITICAL: Subtract 1 for the status bar and 1 for the separator newline
			Height(m.termHeight - 2).
			// Width remains m.termWidth - 2 (for padding/borders if you add them)
			Width(m.termWidth).
			Render(m.shellOutput)

		s += renderedShell

	}
	return s
}

// readShellCmd is the command that reads output from the shell session.
// it runs continuosly until the session closes or an error occurs.
func readShellCmd(stdout io.Reader) tea.Cmd {
	return func() tea.Msg {
		// create a small buffer and read loop.
		buf := make([]byte, 1024)
		n, err := stdout.Read(buf)
		for {

			if n > 0 {
				data := buf[:n]
				cleanData := bytes.ReplaceAll(data, []byte{'\r'}, []byte{})
				// send the data back to the TUI update loop.
				return shellOutputMsg(append([]byte{}, cleanData...))
			}
			if err != nil {
				if err == io.EOF {
					return shellExitMsg{Err: errors.New("shell session closed (EOF)")}
				}
				// session closed or error occurred.
				return shellExitMsg{Err: fmt.Errorf("shell session closed: %w", err)}
			}
		}
	}
}

// startShellCmd is the command that sets up the PTY and starts the shell.
func startShellCmd(c *ssh.Client, conn *Connection, width, height int) tea.Cmd {
	return func() tea.Msg {
		session, err := c.NewSession()
		if err != nil {
			return shellExitMsg{Err: fmt.Errorf("failed to create session: %w", err)}
		}
		// 1. setup input: pipe TUI's input directly to the session's Stdin.
		stdinPipe, err := session.StdinPipe()
		if err != nil {
			session.Close()
			return shellExitMsg{Err: fmt.Errorf("failed to get stdin pipe: %w", err)}
		}
		// 4. setup output (StdoutPipe)
		stdoutPipe, err := session.StdoutPipe()
		if err != nil {
			session.Close()
			return shellExitMsg{Err: fmt.Errorf("failed to get stdout pipe: %w", err)}
		}
		// 2. request PTY (Psuedo-Terminal)
		modes := ssh.TerminalModes{
			ssh.ECHO:   1, // enable enchoing.
			ssh.ICANON: 1,
			ssh.ISIG:   1,
			ssh.ICRNL:  1,
		}

		// use a standard terminal type like "xterm" or "vt100"
		if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
			session.Close()
			return shellExitMsg{Err: fmt.Errorf("request for pty failed: %w", err)}
		}

		// 3. start the shell.
		if err := session.Shell(); err != nil {
			session.Close()
			return shellExitMsg{Err: fmt.Errorf("failed to start shell: %w", err)}
		}

		// the shell is running. save the session and return a message to start reading output.
		return shellReadyMsg{
			session: session,
			stdin:   stdinPipe,
			stdout:  stdoutPipe,
		}
	}
}

func sendMsgCmd(msg tea.Msg) tea.Cmd {
	return func() tea.Msg {
		return msg
	}
}

func main() {
	p := tea.NewProgram(InitialModel(), tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v", err)
		os.Exit(1)
	}
}
