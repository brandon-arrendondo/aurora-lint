# Screenshots

Place TUI screenshots here for the developer guide.

## Required Screenshots

1. **violations-tab.png** - Violations tab with violations grouped by file, showing the source preview panel on the right
2. **configuration-tab.png** - Configuration tab showing CERT C rule categories with toggle controls

## How to Capture

```bash
# Launch interactive mode on a project with violations
aurora-lint /path/to/c-project -d /path/to/c-project --interactive

# In the TUI:
# 1. Press 's' to scan
# 2. Press '3' to group by file
# 3. Press 'p' to show preview panel
# 4. Take screenshot -> violations-tab.png

# 5. Press 'c' to switch to Configuration tab
# 6. Take screenshot -> configuration-tab.png
```

Recommended terminal size: 120x40 or larger for best results.
