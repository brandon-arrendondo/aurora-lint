# UI Module

This module provides the interactive terminal user interface for aurora-lint using the ratatui framework.

## Overview

The UI module implements a modern, responsive terminal interface that allows users to:
- View and navigate through detected violations
- Filter results by file or rule type
- Export violations to various formats
- Suppress false positives
- View detailed violation information

## Architecture

### Main Components

- **`TerminalUI`** - Main UI struct that manages the application state and rendering
- **Event Loop** - Handles keyboard input and user interactions
- **Layout Manager** - Organizes UI panels and responsive layouts
- **Violation Viewer** - Displays violations in a scrollable list with syntax highlighting

## Key Features

### Navigation
- Vim-style navigation (j/k for up/down)
- Page-based scrolling for large result sets
- Jump to first/last with Home/End keys
- Context-aware focus management

### Filtering
- File-based filtering to focus on specific source files
- Rule-based filtering to examine specific violation types
- Real-time filter updates

### Actions
- **Scan** - Trigger analysis of the codebase
- **Export** - Save violations to CSV or Excel
- **Suppress** - Mark violations as false positives
- **Details** - View expanded violation information with code context

## UI Layout

```
┌─────────────────────────────────────────┐
│            Header Bar                   │
├─────────────────────────────────────────┤
│                                         │
│         Violations List                 │
│                                         │
├─────────────────────────────────────────┤
│         Violation Details               │
│         (Code snippet, line info)       │
├─────────────────────────────────────────┤
│         Status Bar / Help               │
└─────────────────────────────────────────┘
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `s` | Scan for violations |
| `e` | Export to CSV |
| `E` | Export to Excel |
| `x` | Suppress violation |
| `X` | Generate suppression file |
| `f` | Toggle file filter |
| `r` | Toggle rule filter |
| `q` | Quit application |
| `Tab` | Switch focus between panels |
| `↑/↓` | Navigate list |
| `Enter` | View details |

## Color Scheme

- **Red** - High severity violations
- **Yellow** - Medium severity violations
- **Blue** - Low severity violations
- **Green** - Successfully processed files
- **Gray** - Suppressed violations

## Dependencies

- `ratatui` - Terminal UI framework
- `crossterm` - Cross-platform terminal manipulation
- `tokio` - Async runtime for event handling

## Customization

The UI appearance and behavior can be customized by modifying:
- Color themes in the rendering functions
- Layout percentages for panel sizes
- Keybinding mappings in the event handler