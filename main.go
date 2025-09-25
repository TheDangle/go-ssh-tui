package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
)

// loadConnectionsCmd is a command that loads our connections asynchronously.
func loadConnectionsCmd() tea.Msg {
	connections, err := loadConnections()
	if err != nil {
		fmt.Printf("Error loading connections: %v\n", err)
		os.Exit(1)
	}
	return connectionsLoadedMsg(connections)
}

const (
	listView state = iota
	formView
)

// model is the main application state.
// It holds our list of connections and the list component itself.
type model struct {
	connections []Connection
	list        list.Model
	inputs      []textinput.Model
	state       state
	focusIndex  int
}

// InitialModel returns the starting state of our TUI application.
func InitialModel() model {
	// We create a new list component.
	l := list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0)
	l.Title = "SSH Connection Manager (press 'a' to add)"
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

	return model{
		list:       l,
		inputs:     inputs,
		state:      listView,
		focusIndex: 0,
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
	}
	switch m.state {
	case listView:
		return m.updateList(msg)
	case formView:
		return m.updateForm(msg)
	}

	return m, nil
}

// View returns the string representation of our application's current state.
func (m model) View() string {
	return m.list.View()
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
			return m, nil
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":
			// Corrected from `selectedItem` to `SelectedItem`.
			if len(m.list.Items()) > 0 {
				selectedItem := m.list.SelectedItem().(item)
				fmt.Printf("Connecting to: %s...\n", selectedItem.connection.Name)
				return m, tea.Quit
			}
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

func main() {
	p := tea.NewProgram(InitialModel(), tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v", err)
		os.Exit(1)
	}
}
