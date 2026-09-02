use anyhow::{Context, Result};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, MouseEvent,
        MouseEventKind,
    },
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen, SetTitle,
    },
    tty::IsTty,
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::PathBuf;
use tree_sitter::Node;

use crate::analyze::suppression::SuppressionManager;
use crate::manifest::{RuleCategory, RuleConfig, RuleManifest, Severity};
use crate::rules::{RuleRegistry, RuleViolation};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq)]
enum SortMode {
    Default,     // Order of operation (current setup)
    ViolationId, // Sorted by violation ID alphabetically
    FilePath,    // Sorted by path/filename alphabetically
    FileName,    // Sorted by filename only alphabetically
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Violations,
    Configuration,
}

impl SortMode {
    fn name(&self) -> &str {
        match self {
            SortMode::Default => "Default",
            SortMode::ViolationId => "Violation ID",
            SortMode::FilePath => "File Path",
            SortMode::FileName => "File Name",
        }
    }
}

#[derive(Clone)]
struct ConfigItem {
    rule_id: String,
    config: RuleConfig,
    level: usize, // 0 for category, 1 for rule
    is_category: bool,
}

#[derive(Clone)]
enum GroupItem {
    Group {
        name: String,
        expanded: bool,
        items: Vec<GroupItem>,
        level: usize,
    },
    Violation {
        original_index: usize,
        violation: RuleViolation,
        level: usize,
    },
    CleanFile {
        file_path: String,
        level: usize,
    },
}

impl GroupItem {
    fn level(&self) -> usize {
        match self {
            GroupItem::Group { level, .. } => *level,
            GroupItem::Violation { level, .. } => *level,
            GroupItem::CleanFile { level, .. } => *level,
        }
    }

    fn is_group(&self) -> bool {
        matches!(self, GroupItem::Group { .. })
    }
}

/// Extract the CERT category prefix from a rule ID for folder/category nesting.
///
/// The category is the leading run of alphabetic characters, which matches the
/// `src/rules/cert_c/<CATEGORY>/` folder layout (e.g. `ARR30-C` -> `ARR`,
/// `API00-C` -> `API`). Falls back to the full rule ID if it has no alphabetic
/// prefix.
fn rule_category(rule_id: &str) -> String {
    let prefix: String = rule_id
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    if prefix.is_empty() {
        rule_id.to_string()
    } else {
        prefix
    }
}

#[derive(Clone)]
struct SuppressionSummary {
    file_path: String,
    violations: Vec<ViolationSuppression>,
}

#[derive(Clone)]
struct ViolationSuppression {
    rule_id: String,
    line: usize,
    code_preview: String,
    hash: String,
}

/// The interactive terminal UI's full state: violations, suppressions,
/// config editing, and the currently active tab/dialog.
pub struct TerminalUI {
    repo_path: String,
    manifest: RuleManifest,
    registry: RuleRegistry,
    directories: Vec<String>,
    include_paths: Vec<String>,
    violations: Vec<RuleViolation>,
    suppressed_violations: Vec<RuleViolation>, // Violations that are suppressed
    clean_files: Vec<String>,                  // Files that were scanned but had no violations
    show_suppressed: bool,                     // Toggle to show/hide suppressed violations
    show_clean_files: bool,                    // Toggle to show/hide files with no violations
    combined_violations: Vec<RuleViolation>,   // Combined active + suppressed for display
    sorted_violations: Vec<(usize, RuleViolation)>, // (original_index, violation)
    grouped_items: Vec<GroupItem>,             // Tree structure for grouping
    flat_display_items: Vec<GroupItem>,        // Flattened for display (only visible items)
    selected_violation: ListState,
    checked_violations: HashSet<usize>,
    show_save_dialog: bool,
    save_filename: String,
    show_file_preview: bool,
    preview_focused: bool,
    preview_scroll_offset: usize,
    sort_mode: SortMode,
    sort_ascending: bool,
    // Configuration tab fields
    current_tab: Tab,
    config_items: Vec<ConfigItem>,
    selected_config: ListState,
    config_groups_expanded: HashMap<String, bool>,
    show_save_config_dialog: bool,
    save_config_filename: String,
    // Suppression dialog fields
    show_suppression_dialog: bool,
    suppression_summary: Vec<SuppressionSummary>,
    uncommitted_files: Vec<String>,
    // Progress dialog fields
    show_progress_dialog: bool,
    progress_current_file: usize,
    progress_total_files: usize,
    progress_file_path: String,
    progress_rule_id: String,
    scan_cancellation: Arc<AtomicBool>,
}

impl TerminalUI {
    /// Build the UI's initial state (config items, empty violation lists)
    /// for `repo_path`; the actual scan happens once [`Self::run`] starts.
    pub fn new(
        repo_path: &str,
        manifest: RuleManifest,
        directories: &[String],
        include_paths: &[String],
    ) -> Result<Self> {
        let registry = RuleRegistry::new();
        let mut selected_violation = ListState::default();
        selected_violation.select(Some(0));

        let mut selected_config = ListState::default();
        selected_config.select(Some(0));

        // Build config items from manifest
        let config_items = Self::build_config_items(&manifest);
        let config_groups_expanded = Self::init_config_groups(&manifest);

        Ok(Self {
            repo_path: repo_path.to_string(),
            manifest,
            registry,
            directories: directories.to_vec(),
            include_paths: include_paths.to_vec(),
            violations: Vec::new(),
            suppressed_violations: Vec::new(),
            clean_files: Vec::new(),
            show_suppressed: false,
            show_clean_files: false,
            combined_violations: Vec::new(),
            sorted_violations: Vec::new(),
            grouped_items: Vec::new(),
            flat_display_items: Vec::new(),
            selected_violation,
            checked_violations: HashSet::new(),
            show_save_dialog: false,
            save_filename: String::from("violations.xlsx"),
            show_file_preview: false, // Default to not showing preview
            preview_focused: false,   // Default focus on violations list
            preview_scroll_offset: 0,
            sort_mode: SortMode::Default,
            sort_ascending: true, // A-Z by default
            current_tab: Tab::Violations,
            config_items,
            selected_config,
            config_groups_expanded,
            show_save_config_dialog: false,
            save_config_filename: String::from("rules_templates/rules-all.toml"),
            show_suppression_dialog: false,
            suppression_summary: Vec::new(),
            uncommitted_files: Vec::new(),
            show_progress_dialog: false,
            progress_current_file: 0,
            progress_total_files: 0,
            progress_file_path: String::new(),
            progress_rule_id: String::new(),
            scan_cancellation: Arc::new(AtomicBool::new(false)),
        })
    }

    fn build_config_items(manifest: &RuleManifest) -> Vec<ConfigItem> {
        let mut items = Vec::new();
        let mut grouped: HashMap<String, Vec<(String, RuleConfig)>> = HashMap::new();

        // Group rules by category (prefix)
        for (rule_id, config) in &manifest.rules.cert_c {
            let category = rule_category(rule_id);
            grouped
                .entry(category)
                .or_default()
                .push((rule_id.clone(), config.clone()));
        }

        // Sort categories and build items
        let mut categories: Vec<_> = grouped.keys().cloned().collect();
        categories.sort();

        for category in categories {
            // Add category header
            items.push(ConfigItem {
                rule_id: category.clone(),
                config: RuleConfig {
                    enabled: true,
                    severity: None, // Categories don't have severity
                    description: Some(format!("{} Rules", category)),
                    category: Some(RuleCategory::Rule),
                    cert_id: None,
                    parameters: None,
                },
                level: 0,
                is_category: true,
            });

            // Add sorted rules in this category
            let mut rules = grouped.get(&category).unwrap().clone();
            rules.sort_by(|a, b| a.0.cmp(&b.0));

            for (rule_id, config) in rules {
                items.push(ConfigItem {
                    rule_id,
                    config,
                    level: 1,
                    is_category: false,
                });
            }
        }

        items
    }

    fn init_config_groups(manifest: &RuleManifest) -> HashMap<String, bool> {
        let mut groups = HashMap::new();

        // Initialize all groups as collapsed
        for rule_id in manifest.rules.cert_c.keys() {
            let category = rule_category(rule_id);
            groups.entry(category).or_insert(false);
        }

        groups
    }

    fn get_visible_config_items(&self) -> Vec<ConfigItem> {
        let mut visible = Vec::new();

        let mut skip_until_next_category = false;
        for item in &self.config_items {
            if item.is_category {
                visible.push(item.clone());
                let expanded = self
                    .config_groups_expanded
                    .get(&item.rule_id)
                    .copied()
                    .unwrap_or(false);
                skip_until_next_category = !expanded;
            } else if !skip_until_next_category {
                visible.push(item.clone());
            }
        }

        visible
    }

    /// Run the interactive terminal UI's main loop. Errors if stdout isn't
    /// a terminal.
    pub fn run(&mut self) -> Result<()> {
        // Check if stdout is a terminal before attempting to use interactive mode
        if !io::stdout().is_tty() {
            return Err(anyhow::anyhow!(
                "Interactive mode requires a terminal. Please run without --interactive flag or from a proper terminal."
            ));
        }

        enable_raw_mode()
            .context("Failed to enable raw mode - ensure you're running in a proper terminal")?;
        let mut stdout = io::stdout();
        execute!(
            stdout,
            SetTitle("sqc - Software Code Quality"),
            EnterAlternateScreen,
            EnableMouseCapture
        )
        .context("Failed to setup terminal - ensure you're running in a proper terminal")?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal =
            Terminal::new(backend).context("Failed to initialize terminal backend")?;

        let result = self.run_app(&mut terminal);

        // Always try to restore terminal state, even if there was an error
        let _ = disable_raw_mode();
        let _ = execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let _ = terminal.show_cursor();

        result
    }

    fn run_app<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        loop {
            terminal.draw(|f| self.ui(f))?;

            match event::read()? {
                Event::Key(key) => {
                    if self.show_progress_dialog {
                        self.handle_progress_dialog_key(key);
                    } else if self.show_save_dialog {
                        self.handle_save_dialog_key(key);
                    } else if self.show_suppression_dialog {
                        self.handle_suppression_dialog_key(key);
                    } else if self.show_save_config_dialog {
                        self.handle_save_config_dialog_key(key);
                    } else if self.handle_main_key(key, terminal)? {
                        return Ok(());
                    }
                }
                Event::Mouse(mouse_event)
                    // Only handle mouse events when not in save dialog
                    if !self.show_save_dialog =>
                {
                    self.handle_mouse_event(mouse_event);
                }
                _ => {}
            }
        }
    }

    /// ESC requests cancellation of an in-progress scan; the progress dialog
    /// hides itself automatically when the scan completes.
    fn handle_progress_dialog_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.scan_cancellation.store(true, Ordering::Relaxed);
        }
    }

    fn handle_save_dialog_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                // Save the file (CSV or Excel based on extension)
                let path = PathBuf::from(&self.save_filename);
                let _ = self.export_violations(&path); // Ignore errors for now
                self.show_save_dialog = false;
            }
            KeyCode::Esc => {
                self.show_save_dialog = false;
            }
            KeyCode::Backspace => {
                self.save_filename.pop();
            }
            KeyCode::Char(c) => {
                self.save_filename.push(c);
            }
            _ => {}
        }
    }

    fn handle_suppression_dialog_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') => {
                // Confirm suppression generation
                let _ = self.apply_suppressions(); // Ignore errors for now
                self.show_suppression_dialog = false;
            }
            KeyCode::Esc | KeyCode::Char('n') => {
                self.show_suppression_dialog = false;
            }
            _ => {}
        }
    }

    fn handle_save_config_dialog_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                // Save the configuration file
                let path = PathBuf::from(&self.save_config_filename);
                let _ = self.export_config(&path); // Ignore errors for now
                self.show_save_config_dialog = false;
            }
            KeyCode::Esc => {
                self.show_save_config_dialog = false;
            }
            KeyCode::Backspace => {
                self.save_config_filename.pop();
            }
            KeyCode::Char(c) => {
                self.save_config_filename.push(c);
            }
            _ => {}
        }
    }

    fn handle_mouse_event(&mut self, mouse_event: MouseEvent) {
        match mouse_event.kind {
            MouseEventKind::ScrollUp => {
                if self.preview_focused && self.show_file_preview {
                    self.preview_scroll_up();
                } else {
                    self.scroll_up();
                }
            }
            MouseEventKind::ScrollDown => {
                if self.preview_focused && self.show_file_preview {
                    self.preview_scroll_down();
                } else {
                    self.scroll_down();
                }
            }
            _ => {}
        }
    }

    /// Handle a key press in the main (no-dialog) state. Returns `Ok(true)`
    /// when the application should quit.
    fn handle_main_key<B: Backend>(
        &mut self,
        key: KeyEvent,
        terminal: &mut Terminal<B>,
    ) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::Down
            | KeyCode::Up
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Left
            | KeyCode::Right => self.handle_navigation_key(key),
            KeyCode::Char('1')
            | KeyCode::Char('2')
            | KeyCode::Char('3')
            | KeyCode::Char('4')
            | KeyCode::Char('r') => self.handle_sort_key(key),
            _ => self.handle_action_key(key, terminal)?,
        }
        Ok(false)
    }

    /// Arrow / page navigation, dispatched by current tab and preview focus.
    fn handle_navigation_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Down => {
                if self.current_tab == Tab::Configuration {
                    self.config_scroll_down();
                } else if self.preview_focused && self.show_file_preview {
                    self.preview_scroll_down();
                } else {
                    self.select_next_violation();
                }
            }
            KeyCode::Up => {
                if self.current_tab == Tab::Configuration {
                    self.config_scroll_up();
                } else if self.preview_focused && self.show_file_preview {
                    self.preview_scroll_up();
                } else {
                    self.select_prev_violation();
                }
            }
            KeyCode::PageUp => {
                if self.current_tab == Tab::Configuration {
                    // Page up in configuration - move by 10 items
                    for _ in 0..10 {
                        self.config_scroll_up();
                    }
                } else if self.preview_focused && self.show_file_preview {
                    // Page up in preview - scroll by 10 lines
                    self.preview_scroll_offset = self.preview_scroll_offset.saturating_sub(10);
                } else {
                    self.page_up_violations();
                }
            }
            KeyCode::PageDown => {
                if self.current_tab == Tab::Configuration {
                    // Page down in configuration - move by 10 items
                    for _ in 0..10 {
                        self.config_scroll_down();
                    }
                } else if self.preview_focused && self.show_file_preview {
                    // Page down in preview - scroll by 10 lines
                    self.preview_scroll_offset += 10;
                } else {
                    self.page_down_violations();
                }
            }
            KeyCode::Left => {
                if self.current_tab == Tab::Configuration {
                    // Collapse config group
                    self.toggle_config_group(false);
                } else if !self.preview_focused {
                    // Collapse group if focused on a group
                    self.toggle_group_expand(false);
                }
            }
            KeyCode::Right => {
                if self.current_tab == Tab::Configuration {
                    // Expand config group
                    self.toggle_config_group(true);
                } else if !self.preview_focused {
                    // Expand group if focused on a group
                    self.toggle_group_expand(true);
                }
            }
            _ => {}
        }
    }

    /// Move selection to the next violation, wrapping to the top.
    fn select_next_violation(&mut self) {
        let i = match self.selected_violation.selected() {
            Some(i) => {
                if i >= self.flat_display_items.len().saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.selected_violation.select(Some(i));
        // Reset preview scroll when changing violations
        self.preview_scroll_offset = 0;
    }

    /// Move selection to the previous violation, wrapping to the bottom.
    fn select_prev_violation(&mut self) {
        let i = match self.selected_violation.selected() {
            Some(i) => {
                if i == 0 {
                    self.flat_display_items.len().saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.selected_violation.select(Some(i));
        // Reset preview scroll when changing violations
        self.preview_scroll_offset = 0;
    }

    /// Move selection up by a page (10 items), clamped to the top.
    fn page_up_violations(&mut self) {
        let page_size = 10;
        let i = match self.selected_violation.selected() {
            Some(i) => i.saturating_sub(page_size),
            None => 0,
        };
        self.selected_violation.select(Some(i));
        // Reset preview scroll when changing violations
        self.preview_scroll_offset = 0;
    }

    /// Move selection down by a page (10 items), clamped to the bottom.
    fn page_down_violations(&mut self) {
        let page_size = 10;
        let max_index = self.flat_display_items.len().saturating_sub(1);
        let i = match self.selected_violation.selected() {
            Some(i) => {
                if i + page_size >= max_index {
                    max_index
                } else {
                    i + page_size
                }
            }
            None => 0,
        };
        self.selected_violation.select(Some(i));
        // Reset preview scroll when changing violations
        self.preview_scroll_offset = 0;
    }

    /// Sort-mode and sort-direction keys (1-4, r), then re-sort.
    fn handle_sort_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('1') => self.sort_mode = SortMode::Default,
            KeyCode::Char('2') => self.sort_mode = SortMode::ViolationId,
            KeyCode::Char('3') => self.sort_mode = SortMode::FilePath,
            KeyCode::Char('4') => self.sort_mode = SortMode::FileName,
            KeyCode::Char('r') => self.sort_ascending = !self.sort_ascending,
            _ => return,
        }
        if self.show_suppressed {
            self.update_combined_violations();
        }
        self.update_sort();
    }

    /// Action keys (scan, suppress, export, selection, preview, tab switch).
    fn handle_action_key<B: Backend>(
        &mut self,
        key: KeyEvent,
        terminal: &mut Terminal<B>,
    ) -> Result<()> {
        match key.code {
            KeyCode::Char('s')
                // Trigger scan (only in Violations tab)
                if self.current_tab == Tab::Violations =>
            {
                self.scan_repository(terminal)?;
            }
            KeyCode::Char('i')
                // Ignore/suppress selected violations
                if self.current_tab == Tab::Violations && !self.checked_violations.is_empty() =>
            {
                self.initiate_suppression();
            }
            KeyCode::Char('h')
                // Toggle hidden items visibility (suppressed violations and clean files)
                if self.current_tab == Tab::Violations =>
            {
                self.show_suppressed = !self.show_suppressed;
                self.show_clean_files = !self.show_clean_files;
                if self.show_suppressed {
                    self.update_combined_violations();
                }
                self.update_display_violations();
                self.update_sort();
            }
            KeyCode::Char(' ') => self.handle_space_key(),
            KeyCode::Char('e') => {
                if self.current_tab == Tab::Configuration {
                    // Show save dialog for exporting configuration
                    self.show_save_config_dialog = true;
                } else if !self.checked_violations.is_empty() {
                    // Show save dialog for exporting selected violations to CSV
                    self.show_save_dialog = true;
                }
            }
            KeyCode::Char('a') | KeyCode::Char('A') => self.handle_select_all_key(key),
            KeyCode::Char('n') | KeyCode::Char('N') => self.handle_deselect_all_key(key),
            KeyCode::Char('p') => {
                // Toggle file preview
                self.show_file_preview = !self.show_file_preview;
                if !self.show_file_preview {
                    self.preview_focused = false; // Reset focus if preview is hidden
                }
            }
            KeyCode::Tab
                // Switch focus between violations list and file preview (only in Violations tab)
                if self.current_tab == Tab::Violations && self.show_file_preview =>
            {
                self.preview_focused = !self.preview_focused;
            }
            KeyCode::Char('c') => {
                // Switch to Configuration tab
                self.current_tab = Tab::Configuration;
                self.preview_focused = false;
            }
            KeyCode::Char('v') => {
                // Switch to Violations tab
                self.current_tab = Tab::Violations;
            }
            _ => {}
        }
        Ok(())
    }

    /// Space toggles a config item, a group's expansion, or a violation's checkbox.
    fn handle_space_key(&mut self) {
        if self.current_tab == Tab::Configuration {
            // Toggle rule enabled/disabled in Configuration tab
            self.toggle_config_item();
            return;
        }
        // Check if it's a group item - if so, toggle expand/collapse
        let Some(display_index) = self.selected_violation.selected() else {
            return;
        };
        let Some(selected_item) = self.flat_display_items.get(display_index) else {
            return;
        };
        if selected_item.is_group() {
            // Toggle group expansion
            if let GroupItem::Group { expanded, .. } = selected_item {
                self.toggle_group_expand(!expanded);
            }
        } else if let GroupItem::Violation { original_index, .. } = selected_item {
            // Toggle checkbox for selected violation
            if self.checked_violations.contains(original_index) {
                self.checked_violations.remove(original_index);
            } else {
                self.checked_violations.insert(*original_index);
            }
        }
    }

    /// 'a' selects all violations; Shift+A selects all within the current group.
    fn handle_select_all_key(&mut self, key: KeyEvent) {
        if key
            .modifiers
            .contains(crossterm::event::KeyModifiers::SHIFT)
        {
            // Shift+A: Select all violations in current group (only for grouped modes)
            if self.sort_mode != SortMode::Default {
                self.select_all_in_current_group();
            }
        } else {
            // Regular 'a': Select all violations (using original indices)
            self.checked_violations = self
                .flat_display_items
                .iter()
                .filter_map(|item| {
                    if let GroupItem::Violation { original_index, .. } = item {
                        Some(*original_index)
                    } else {
                        None
                    }
                })
                .collect();
        }
    }

    /// 'n' deselects all violations; Shift+N deselects all within the current group.
    fn handle_deselect_all_key(&mut self, key: KeyEvent) {
        if key
            .modifiers
            .contains(crossterm::event::KeyModifiers::SHIFT)
        {
            // Shift+N: Deselect all violations in current group (only for grouped modes)
            if self.sort_mode != SortMode::Default {
                self.deselect_all_in_current_group();
            }
        } else {
            // Regular 'n': Deselect all violations
            self.checked_violations.clear();
        }
    }

    fn ui(&mut self, f: &mut Frame) {
        if self.show_progress_dialog {
            self.render_progress_dialog(f);
            return;
        }

        if self.show_save_dialog {
            self.render_save_dialog(f);
            return;
        }

        if self.show_save_config_dialog {
            self.render_save_config_dialog(f);
            return;
        }

        if self.show_suppression_dialog {
            self.render_suppression_dialog(f);
            return;
        }

        match self.current_tab {
            Tab::Violations => self.render_violations_tab(f),
            Tab::Configuration => self.render_configuration_tab(f),
        }
    }

    fn render_violations_tab(&mut self, f: &mut Frame) {
        let chunks = if self.show_file_preview {
            // Split vertically: violations, preview, footer
            Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Percentage(50), // Violations list
                    Constraint::Percentage(50), // File preview
                    Constraint::Length(5),      // Footer (2 lines)
                ])
                .split(f.area())
        } else {
            // Original layout: violations, footer
            Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Min(10),   // Violations list
                    Constraint::Length(5), // Footer (2 lines)
                ])
                .split(f.area())
        };

        // Violations list
        let violations: Vec<ListItem> = self
            .flat_display_items
            .iter()
            .map(|item| self.build_display_item_list_entry(item))
            .collect();

        // Create dynamic violations title with current violation details
        let violations_title = self.build_violations_title();

        let violations_block = if !self.preview_focused || !self.show_file_preview {
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(violations_title)
        } else {
            Block::default()
                .borders(Borders::ALL)
                .title(violations_title)
        };

        let violations_list = List::new(violations)
            .block(violations_block)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");

        f.render_stateful_widget(violations_list, chunks[0], &mut self.selected_violation);

        // File preview panel (only if enabled)
        if self.show_file_preview {
            self.render_file_preview(f, chunks[1]);
        }

        // Footer
        let footer = Paragraph::new(vec![
            Line::from(vec![
                Span::raw("("),
                Span::styled("<ESC>/q", Style::default().fg(Color::Yellow)),
                Span::raw(")uit | ("),
                Span::styled("c", Style::default().fg(Color::Yellow)),
                Span::raw(")onfig | ("),
                Span::styled("s", Style::default().fg(Color::Yellow)),
                Span::raw(")can | ("),
                Span::styled("h", Style::default().fg(Color::Yellow)),
                Span::raw(")idden | ("),
                Span::styled("f", Style::default().fg(Color::Yellow)),
                Span::raw(")ilter | ("),
                Span::styled("r", Style::default().fg(Color::Yellow)),
                Span::raw(")ule filter"),
            ]),
            Line::from(vec![
                Span::raw("SELECTION: ("),
                Span::styled("<space>", Style::default().fg(Color::Yellow)),
                Span::raw(")select | ("),
                Span::styled("a", Style::default().fg(Color::Yellow)),
                Span::raw(")ll OR ("),
                Span::styled("n", Style::default().fg(Color::Yellow)),
                Span::raw(")one | ("),
                Span::styled("x", Style::default().fg(Color::Yellow)),
                Span::raw(")suppress OR ("),
                Span::styled("e", Style::default().fg(Color::Yellow)),
                Span::raw(")xport"),
            ]),
            Line::from(vec![
                Span::raw("VIEW: ("),
                Span::styled("p", Style::default().fg(Color::Yellow)),
                Span::raw(")review | ("),
                Span::styled("<tab>", Style::default().fg(Color::Yellow)),
                Span::raw(")focus | ("),
                Span::styled("1-4", Style::default().fg(Color::Yellow)),
                Span::raw(")sort"),
            ]),
        ])
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(ratatui::text::Line::from(vec![
                    Span::styled("✓", Style::default().fg(Color::Green)),
                    Span::styled("{", Style::default().fg(Color::Cyan)),
                    Span::raw("SQC"),
                    Span::styled("}", Style::default().fg(Color::Cyan)),
                    Span::raw(" - Software Code Quality"),
                ])),
        );

        let footer_index = if self.show_file_preview { 2 } else { 1 };
        f.render_widget(footer, chunks[footer_index]);
    }

    /// Build a single `ListItem` for the violations list from a display item
    /// (group header, violation row, or clean-file row).
    fn build_display_item_list_entry(&self, item: &GroupItem) -> ListItem<'static> {
        match item {
            GroupItem::Group {
                name,
                expanded,
                level,
                ..
            } => {
                let indent = "  ".repeat(*level);
                let expand_indicator = if *expanded { "▼ " } else { "▶ " };
                ListItem::new(vec![Line::from(vec![
                    Span::raw(indent),
                    Span::styled(
                        expand_indicator.to_string(),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(
                        name.clone(),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                ])])
            }
            GroupItem::Violation {
                original_index,
                violation,
                level,
            } => self.build_violation_list_entry(*original_index, violation, *level),
            GroupItem::CleanFile { file_path, level } => {
                // Get relative path and filename
                let relative_path = self.get_relative_path(file_path);
                let filename = std::path::Path::new(file_path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                let indent = "  ".repeat(*level);

                let spans = vec![
                    Span::raw(indent),
                    Span::styled("[✓] ", Style::default().fg(Color::Green)),
                    Span::styled(
                        "CLEAN",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" - "),
                    Span::styled(filename, Style::default().fg(Color::White)),
                    Span::raw(" ("),
                    Span::styled(relative_path, Style::default().fg(Color::Gray)),
                    Span::raw(") "),
                    Span::styled(
                        "[NO VIOLATIONS]",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::ITALIC),
                    ),
                ];

                ListItem::new(vec![Line::from(spans)])
            }
        }
    }

    /// Build the `ListItem` for a single violation row, including the
    /// suppressed-dimming styling.
    fn build_violation_list_entry(
        &self,
        original_index: usize,
        violation: &RuleViolation,
        level: usize,
    ) -> ListItem<'static> {
        let is_suppressed = self.show_suppressed && self.is_violation_suppressed(violation);

        let severity_color = match violation.severity {
            crate::manifest::Severity::Critical => Color::Red,
            crate::manifest::Severity::High => Color::LightRed,
            crate::manifest::Severity::Medium => Color::Yellow,
            crate::manifest::Severity::Low => Color::Blue,
        };

        let checkbox = if self.checked_violations.contains(&original_index) {
            "[✓] "
        } else {
            "[ ] "
        };

        // Get relative path and filename
        let relative_path = self.get_relative_path(&violation.file_path);
        let filename = std::path::Path::new(&violation.file_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let indent = "  ".repeat(level);

        let mut spans = vec![
            Span::raw(indent),
            Span::styled(checkbox, Style::default().fg(Color::Green)),
        ];

        if is_suppressed {
            // Add suppression indicator
            spans.push(Span::styled("[S] ", Style::default().fg(Color::DarkGray)));
            // Use dimmed colors for suppressed violations
            spans.push(Span::styled(
                violation.rule_id.clone(),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::DIM),
            ));
        } else {
            spans.push(Span::styled(
                violation.rule_id.clone(),
                Style::default()
                    .fg(severity_color)
                    .add_modifier(Modifier::BOLD),
            ));
        }

        spans.extend(vec![
            Span::raw(" - "),
            Span::styled(
                filename,
                if is_suppressed {
                    Style::default().fg(Color::DarkGray)
                } else {
                    Style::default().fg(Color::White)
                },
            ),
            Span::raw(" ("),
            Span::styled(relative_path, Style::default().fg(Color::Gray)),
            Span::raw(":"),
            Span::styled(
                format!("{}:{}", violation.line, violation.column),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(")"),
        ]);

        if is_suppressed {
            spans.push(Span::styled(
                " [SUPPRESSED]",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            ));
        }

        ListItem::new(vec![Line::from(spans)])
    }

    /// "[FOCUSED] " when the violations list (rather than the file preview)
    /// has keyboard focus, else empty.
    fn focus_indicator_text(&self) -> &'static str {
        if !self.preview_focused || !self.show_file_preview {
            "[FOCUSED] "
        } else {
            ""
        }
    }

    /// " [Sort: NAME A-Z/Z-A]" when a non-default sort is active, else empty.
    fn sort_info_text(&self) -> String {
        if self.sort_mode != SortMode::Default {
            format!(
                " [Sort: {} {}]",
                self.sort_mode.name(),
                if self.sort_ascending { "A-Z" } else { "Z-A" }
            )
        } else {
            String::new()
        }
    }

    /// " [Hidden: N suppressed, M clean]" summarizing hidden rows, else empty.
    fn hidden_info_text(&self) -> String {
        if !self.show_suppressed && !self.show_clean_files {
            return String::new();
        }
        let mut items = Vec::new();
        if self.show_suppressed && !self.suppressed_violations.is_empty() {
            items.push(format!("{} suppressed", self.suppressed_violations.len()));
        }
        if self.show_clean_files && !self.clean_files.is_empty() {
            items.push(format!("{} clean", self.clean_files.len()));
        }
        if items.is_empty() {
            String::new()
        } else {
            format!(" [Hidden: {}]", items.join(", "))
        }
    }

    /// Build the violations panel title, appending the currently-selected
    /// violation's rule/location detail when one is selected.
    fn build_violations_title(&self) -> String {
        let focus_indicator = self.focus_indicator_text();
        let sort_info = self.sort_info_text();
        let hidden_info = self.hidden_info_text();

        let selected_violation = self
            .selected_violation
            .selected()
            .and_then(|idx| self.flat_display_items.get(idx))
            .and_then(|item| match item {
                GroupItem::Violation { violation, .. } => Some(violation),
                _ => None,
            });

        let Some(violation) = selected_violation else {
            return format!(
                "Repository: {} | {}Violations{}{}",
                self.repo_path, focus_indicator, sort_info, hidden_info
            );
        };

        let relative_path = self.get_relative_path(&violation.file_path);
        let filename = std::path::Path::new(&violation.file_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let rule_description = self
            .registry
            .get_rule(&violation.rule_id)
            .map(|rule| rule.description())
            .unwrap_or("Unknown rule");

        format!(
            "Repository: {} | {}Violations{}{} - {}: {} - {}:{} ({})",
            self.repo_path,
            focus_indicator,
            sort_info,
            hidden_info,
            violation.rule_id,
            rule_description,
            filename,
            violation.line,
            relative_path
        )
    }

    fn render_save_dialog(&mut self, f: &mut Frame) {
        use ratatui::layout::Rect;

        let area = f.area();
        let popup_area = Rect {
            x: area.width / 4,
            y: area.height / 2 - 3,
            width: area.width / 2,
            height: 6,
        };

        // Clear the popup area
        f.render_widget(
            Block::default()
                .style(Style::default().bg(Color::Black))
                .borders(Borders::ALL)
                .title("Save CSV Export"),
            popup_area,
        );

        let inner_area = Rect {
            x: popup_area.x + 1,
            y: popup_area.y + 1,
            width: popup_area.width - 2,
            height: popup_area.height - 2,
        };

        let dialog_text = vec![
            Line::from("Enter filename (.csv or .xlsx):"),
            Line::from(vec![
                Span::styled(&self.save_filename, Style::default().fg(Color::Yellow)),
                Span::styled("_", Style::default().fg(Color::Green)), // cursor
            ]),
            Line::from(""),
            Line::from("Press Enter to save, Esc to cancel"),
        ];

        let dialog_paragraph = Paragraph::new(dialog_text).style(Style::default().fg(Color::White));

        f.render_widget(dialog_paragraph, inner_area);
    }

    fn render_save_config_dialog(&mut self, f: &mut Frame) {
        let area = f.area();
        let popup_area = Rect {
            x: area.width / 4,
            y: area.height / 2 - 3,
            width: area.width / 2,
            height: 6,
        };

        // Clear the background
        f.render_widget(Clear, popup_area);

        // Render popup border
        let popup_block = Block::default()
            .borders(Borders::ALL)
            .title("Save Configuration")
            .border_style(Style::default().fg(Color::Yellow));

        f.render_widget(popup_block, popup_area);

        let inner_area = Rect {
            x: popup_area.x + 1,
            y: popup_area.y + 1,
            width: popup_area.width - 2,
            height: popup_area.height - 2,
        };

        let dialog_text = vec![
            Line::from("Enter filename (.toml):"),
            Line::from(vec![
                Span::styled(
                    &self.save_config_filename,
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled("_", Style::default().fg(Color::Green)), // cursor
            ]),
            Line::from(""),
            Line::from("Press Enter to save, Esc to cancel"),
        ];

        let dialog_paragraph = Paragraph::new(dialog_text).style(Style::default().fg(Color::White));

        f.render_widget(dialog_paragraph, inner_area);
    }

    fn render_configuration_tab(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(1),    // Config list
                Constraint::Length(3), // Footer
            ])
            .split(f.area());

        // Header with icon
        let header = Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    "✓",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled("{", Style::default().fg(Color::Cyan)),
                Span::styled(
                    "SQC",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("}", Style::default().fg(Color::Cyan)),
            ]),
            Line::from("Software Code Quality"),
            Line::from(format!(
                "Total Rules: {} | Tab: Configuration",
                self.manifest.rules.cert_c.len()
            )),
        ])
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));

        f.render_widget(header, chunks[0]);

        // Configuration list
        let visible_items = self.get_visible_config_items();
        let config_items: Vec<ListItem> = visible_items
            .iter()
            .map(|item| {
                if item.is_category {
                    let expanded = self
                        .config_groups_expanded
                        .get(&item.rule_id)
                        .copied()
                        .unwrap_or(false);
                    let indicator = if expanded { "▼ " } else { "▶ " };
                    ListItem::new(vec![Line::from(vec![
                        Span::styled(indicator, Style::default().fg(Color::Yellow)),
                        Span::styled(
                            &item.rule_id,
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(" Rules"),
                    ])])
                } else {
                    let checkbox = if item.config.enabled {
                        "[✓] "
                    } else {
                        "[ ] "
                    };
                    let indent = "  ".repeat(item.level);

                    // Get severity from config if specified, otherwise from rule default
                    let severity = item
                        .config
                        .severity
                        .clone()
                        .or_else(|| self.registry.get_rule(&item.rule_id).map(|r| r.severity()))
                        .unwrap_or(Severity::Medium);

                    let severity_color = match severity {
                        Severity::Critical => Color::Red,
                        Severity::High => Color::LightRed,
                        Severity::Medium => Color::Yellow,
                        Severity::Low => Color::Blue,
                    };

                    // Get description from config if specified, otherwise from rule default
                    let description = item
                        .config
                        .description
                        .as_deref()
                        .or_else(|| {
                            self.registry
                                .get_rule(&item.rule_id)
                                .map(|r| r.description())
                        })
                        .unwrap_or("No description")
                        .to_string();

                    ListItem::new(vec![Line::from(vec![
                        Span::raw(indent),
                        Span::styled(checkbox, Style::default().fg(Color::Green)),
                        Span::styled(&item.rule_id, Style::default().fg(severity_color)),
                        Span::raw(" - "),
                        Span::styled(description, Style::default().fg(Color::Gray)),
                    ])])
                }
            })
            .collect();

        let config_list = List::new(config_items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Rules Configuration"),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");

        f.render_stateful_widget(config_list, chunks[1], &mut self.selected_config);

        // Footer
        let footer = Paragraph::new(vec![Line::from(vec![
            Span::raw("("),
            Span::styled("q/<ESC>", Style::default().fg(Color::Yellow)),
            Span::raw(")uit | ("),
            Span::styled("v", Style::default().fg(Color::Yellow)),
            Span::raw(")iolations | SELECTION: ("),
            Span::styled("<space>", Style::default().fg(Color::Yellow)),
            Span::raw(")select, [("),
            Span::styled("a", Style::default().fg(Color::Yellow)),
            Span::raw(")ll OR ("),
            Span::styled("n", Style::default().fg(Color::Yellow)),
            Span::raw(")one] | ("),
            Span::styled("e", Style::default().fg(Color::Yellow)),
            Span::raw(")xport |"),
        ])])
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL));

        f.render_widget(footer, chunks[2]);
    }

    fn render_file_preview(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        if let Some(selected_index) = self.selected_violation.selected() {
            if let Some(selected_item) = self.flat_display_items.get(selected_index) {
                if let GroupItem::Violation { violation, .. } = selected_item {
                    // Try to read and display the file content
                    match self.get_file_preview(&violation.file_path, violation.line) {
                        Ok(preview_lines) => {
                            // Apply scroll offset
                            let scrolled_lines: Vec<_> = preview_lines
                                .into_iter()
                                .skip(self.preview_scroll_offset)
                                .collect();

                            let title = if self.preview_focused {
                                format!(
                                    "[FOCUSED] Preview: {} (line {})",
                                    std::path::Path::new(&violation.file_path)
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy(),
                                    violation.line
                                )
                            } else {
                                format!(
                                    "Preview: {} (line {}) - Tab to focus",
                                    std::path::Path::new(&violation.file_path)
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy(),
                                    violation.line
                                )
                            };

                            let block_style = if self.preview_focused {
                                Block::default()
                                    .borders(Borders::ALL)
                                    .border_style(Style::default().fg(Color::Yellow))
                                    .title(title)
                            } else {
                                Block::default().borders(Borders::ALL).title(title)
                            };

                            let preview_paragraph = Paragraph::new(scrolled_lines)
                                .block(block_style)
                                .wrap(ratatui::widgets::Wrap { trim: false });

                            f.render_widget(preview_paragraph, area);
                        }
                        Err(_) => {
                            let error_paragraph = Paragraph::new("Unable to preview file")
                                .block(Block::default().borders(Borders::ALL).title("File Preview"))
                                .style(Style::default().fg(Color::Red));

                            f.render_widget(error_paragraph, area);
                        }
                    }
                } else {
                    // Group selected, no preview
                    let empty_paragraph = Paragraph::new("Select a violation to preview file")
                        .block(Block::default().borders(Borders::ALL).title("File Preview"))
                        .style(Style::default().fg(Color::Gray));

                    f.render_widget(empty_paragraph, area);
                }
            } else {
                // No item selected
                let empty_paragraph = Paragraph::new("Select a violation to preview file")
                    .block(Block::default().borders(Borders::ALL).title("File Preview"))
                    .style(Style::default().fg(Color::Gray));

                f.render_widget(empty_paragraph, area);
            }
        } else {
            // No violations available
            let empty_paragraph = Paragraph::new("No violations to preview")
                .block(Block::default().borders(Borders::ALL).title("File Preview"))
                .style(Style::default().fg(Color::Gray));

            f.render_widget(empty_paragraph, area);
        }
    }

    fn get_file_preview(&self, file_path: &str, target_line: usize) -> Result<Vec<Line<'_>>> {
        let content = fs::read_to_string(file_path)?;
        let lines: Vec<&str> = content.lines().collect();

        // Show context around the target line (5 lines before and after)
        let context_size = 5;
        let start_line = target_line.saturating_sub(context_size).max(1);
        let end_line = (target_line + context_size).min(lines.len());

        let mut preview_lines = Vec::new();

        for line_num in start_line..=end_line {
            if let Some(line_content) = lines.get(line_num - 1) {
                let line_number_str = format!("{:4} ", line_num);

                if line_num == target_line {
                    // Highlight the target line
                    preview_lines.push(Line::from(vec![
                        Span::styled(
                            line_number_str,
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            ">>> ",
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            line_content.to_string(),
                            Style::default().fg(Color::White).bg(Color::Red),
                        ),
                    ]));
                } else {
                    // Regular line
                    preview_lines.push(Line::from(vec![
                        Span::styled(line_number_str, Style::default().fg(Color::Cyan)),
                        Span::styled("    ", Style::default()),
                        Span::styled(line_content.to_string(), Style::default().fg(Color::White)),
                    ]));
                }
            }
        }

        Ok(preview_lines)
    }

    fn scroll_up(&mut self) {
        let i = match self.selected_violation.selected() {
            Some(i) => {
                if i == 0 {
                    self.flat_display_items.len().saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.selected_violation.select(Some(i));
    }

    fn scroll_down(&mut self) {
        let i = match self.selected_violation.selected() {
            Some(i) => {
                if i >= self.flat_display_items.len().saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.selected_violation.select(Some(i));
    }

    fn preview_scroll_up(&mut self) {
        if self.preview_scroll_offset > 0 {
            self.preview_scroll_offset -= 1;
        }
    }

    fn preview_scroll_down(&mut self) {
        self.preview_scroll_offset += 1;
    }

    fn config_scroll_up(&mut self) {
        let visible_items = self.get_visible_config_items();
        let i = match self.selected_config.selected() {
            Some(i) => {
                if i == 0 {
                    visible_items.len().saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.selected_config.select(Some(i));
    }

    fn config_scroll_down(&mut self) {
        let visible_items = self.get_visible_config_items();
        let i = match self.selected_config.selected() {
            Some(i) => {
                if i >= visible_items.len().saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.selected_config.select(Some(i));
    }

    fn toggle_config_item(&mut self) {
        let visible_items = self.get_visible_config_items();
        if let Some(selected_index) = self.selected_config.selected() {
            if let Some(item) = visible_items.get(selected_index) {
                if !item.is_category {
                    // Find the actual config item in our list and toggle it
                    for config_item in &mut self.config_items {
                        if config_item.rule_id == item.rule_id {
                            config_item.config.enabled = !config_item.config.enabled;
                            // Also update the manifest in memory
                            if let Some(manifest_config) = self.manifest.get_rule_mut(&item.rule_id)
                            {
                                manifest_config.enabled = config_item.config.enabled;
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    fn toggle_config_group(&mut self, expand: bool) {
        let visible_items = self.get_visible_config_items();
        if let Some(selected_index) = self.selected_config.selected() {
            if let Some(item) = visible_items.get(selected_index) {
                if item.is_category {
                    self.config_groups_expanded
                        .insert(item.rule_id.clone(), expand);
                }
            }
        }
    }

    fn export_config(&self, path: &PathBuf) -> Result<()> {
        // Build the TOML content
        let toml_content = toml::to_string_pretty(&self.manifest)?;
        fs::write(path, toml_content)?;
        Ok(())
    }

    fn update_sort(&mut self) {
        let active_violations = if self.show_suppressed {
            &self.combined_violations
        } else {
            &self.violations
        };

        self.sorted_violations = active_violations
            .iter()
            .enumerate()
            .map(|(idx, v)| (idx, v.clone()))
            .collect();

        match self.sort_mode {
            SortMode::Default => {
                // Keep original order - no sorting needed, no grouping
                let mut items: Vec<GroupItem> = self
                    .sorted_violations
                    .iter()
                    .map(|(original_index, violation)| GroupItem::Violation {
                        original_index: *original_index,
                        violation: violation.clone(),
                        level: 0,
                    })
                    .collect();

                // Add clean files if they should be shown
                if self.show_clean_files {
                    for file_path in &self.clean_files {
                        items.push(GroupItem::CleanFile {
                            file_path: file_path.clone(),
                            level: 0,
                        });
                    }
                }

                self.grouped_items = items;
            }
            SortMode::ViolationId => {
                self.sorted_violations.sort_by(|a, b| {
                    if self.sort_ascending {
                        a.1.rule_id.cmp(&b.1.rule_id)
                    } else {
                        b.1.rule_id.cmp(&a.1.rule_id)
                    }
                });
                self.group_by_violation_id();
            }
            SortMode::FilePath => {
                let sort_ascending = self.sort_ascending;
                self.sorted_violations.sort_by(|a, b| {
                    if sort_ascending {
                        a.1.file_path.cmp(&b.1.file_path)
                    } else {
                        b.1.file_path.cmp(&a.1.file_path)
                    }
                });
                self.group_by_file_path();
            }
            SortMode::FileName => {
                let sort_ascending = self.sort_ascending;
                self.sorted_violations.sort_by(|a, b| {
                    let name_a = std::path::Path::new(&a.1.file_path)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    let name_b = std::path::Path::new(&b.1.file_path)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    if sort_ascending {
                        name_a.cmp(&name_b)
                    } else {
                        name_b.cmp(&name_a)
                    }
                });
                self.group_by_file_name();
            }
        }

        // Update flat display items
        self.flatten_groups();

        // Reset selection to first item
        if !self.flat_display_items.is_empty() {
            self.selected_violation.select(Some(0));
        }
    }

    fn group_by_violation_id(&mut self) {
        use std::collections::BTreeMap;

        let mut groups: BTreeMap<String, Vec<(usize, RuleViolation)>> = BTreeMap::new();

        for (original_index, violation) in &self.sorted_violations {
            // Extract category (e.g., "ARR" from "ARR30-C")
            let category = rule_category(&violation.rule_id);
            groups
                .entry(category)
                .or_default()
                .push((*original_index, violation.clone()));
        }

        self.grouped_items = if self.sort_ascending {
            groups.into_iter().collect::<Vec<_>>()
        } else {
            groups.into_iter().rev().collect::<Vec<_>>()
        }
        .into_iter()
        .map(|(category, violations)| GroupItem::Group {
            name: category,
            expanded: false,
            items: violations
                .into_iter()
                .map(|(original_index, violation)| GroupItem::Violation {
                    original_index,
                    violation,
                    level: 1,
                })
                .collect(),
            level: 0,
        })
        .collect();
    }

    fn group_by_file_path(&mut self) {
        use std::collections::BTreeMap;

        let mut path_groups: BTreeMap<String, Vec<GroupItem>> = BTreeMap::new();

        for (original_index, violation) in &self.sorted_violations {
            let dir_path = std::path::Path::new(&violation.file_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| ".".to_string());

            path_groups
                .entry(dir_path)
                .or_default()
                .push(GroupItem::Violation {
                    original_index: *original_index,
                    violation: violation.clone(),
                    level: 1,
                });
        }

        // Add clean files if they should be shown
        if self.show_clean_files {
            for file_path in &self.clean_files {
                let dir_path = std::path::Path::new(file_path.as_str())
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| ".".to_string());

                path_groups
                    .entry(dir_path)
                    .or_default()
                    .push(GroupItem::CleanFile {
                        file_path: file_path.clone(),
                        level: 1,
                    });
            }
        }

        self.grouped_items = if self.sort_ascending {
            path_groups.into_iter().collect::<Vec<_>>()
        } else {
            path_groups.into_iter().rev().collect::<Vec<_>>()
        }
        .into_iter()
        .map(|(dir_path, items)| GroupItem::Group {
            name: dir_path,
            expanded: false,
            items,
            level: 0,
        })
        .collect();
    }

    fn group_by_file_name(&mut self) {
        use std::collections::BTreeMap;

        let mut file_groups: BTreeMap<String, Vec<(usize, RuleViolation)>> = BTreeMap::new();

        for (original_index, violation) in &self.sorted_violations {
            let filename = std::path::Path::new(&violation.file_path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            file_groups
                .entry(filename)
                .or_default()
                .push((*original_index, violation.clone()));
        }

        self.grouped_items = if self.sort_ascending {
            file_groups.into_iter().collect::<Vec<_>>()
        } else {
            file_groups.into_iter().rev().collect::<Vec<_>>()
        }
        .into_iter()
        .map(|(filename, violations)| GroupItem::Group {
            name: filename,
            expanded: false,
            items: violations
                .into_iter()
                .map(|(original_index, violation)| GroupItem::Violation {
                    original_index,
                    violation,
                    level: 1,
                })
                .collect(),
            level: 0,
        })
        .collect();
    }

    fn flatten_groups(&mut self) {
        self.flat_display_items.clear();
        self.flatten_groups_recursive(&self.grouped_items.clone());
    }

    fn flatten_groups_recursive(&mut self, items: &[GroupItem]) {
        for item in items {
            match item {
                GroupItem::Group {
                    name: _,
                    expanded,
                    items,
                    level: _,
                } => {
                    self.flat_display_items.push(item.clone());
                    if *expanded {
                        self.flatten_groups_recursive(items);
                    }
                }
                GroupItem::Violation { .. } => {
                    self.flat_display_items.push(item.clone());
                }
                GroupItem::CleanFile { .. } => {
                    self.flat_display_items.push(item.clone());
                }
            }
        }
    }

    fn toggle_group_expand(&mut self, expand: bool) {
        if let Some(selected_index) = self.selected_violation.selected() {
            let selected_item = self.flat_display_items.get(selected_index).cloned();
            if let Some(selected_item) = selected_item {
                if selected_item.is_group() {
                    // Find the corresponding group in grouped_items and toggle it
                    if let GroupItem::Group { name, level, .. } = &selected_item {
                        self.update_grouped_items_expand(name, *level, expand);
                    }
                    self.flatten_groups();

                    // Ensure selection remains valid
                    if selected_index >= self.flat_display_items.len() {
                        let new_index = self.flat_display_items.len().saturating_sub(1);
                        self.selected_violation.select(Some(new_index));
                    }
                } else if !expand {
                    // For left arrow on a child item, find and collapse the parent group
                    if let Some(parent_index) = self.find_parent_group(selected_index) {
                        if let Some(GroupItem::Group { name, level, .. }) =
                            self.flat_display_items.get(parent_index).cloned()
                        {
                            // Collapse the parent group
                            self.update_grouped_items_expand(&name, level, false);
                            self.flatten_groups();

                            // Find the parent group in the new flat list and select it
                            for (i, item) in self.flat_display_items.iter().enumerate() {
                                if let GroupItem::Group {
                                    name: item_name,
                                    level: item_level,
                                    ..
                                } = item
                                {
                                    if item_name == &name && item_level == &level {
                                        self.selected_violation.select(Some(i));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn find_parent_group(&self, child_index: usize) -> Option<usize> {
        // Find the parent group by looking backwards from the child's position
        if child_index == 0 {
            return None;
        }

        // Get the child's level
        let child_level = if let Some(child_item) = self.flat_display_items.get(child_index) {
            child_item.level()
        } else {
            return None;
        };

        // Look backwards for the first group with a lower level
        for i in (0..child_index).rev() {
            if let Some(item) = self.flat_display_items.get(i) {
                if item.is_group() && item.level() < child_level {
                    return Some(i);
                }
            }
        }

        None
    }

    fn update_grouped_items_expand(
        &mut self,
        target_name: &str,
        target_level: usize,
        expand: bool,
    ) {
        for item in &mut self.grouped_items {
            if let GroupItem::Group {
                name,
                expanded,
                level,
                ..
            } = item
            {
                if name == target_name && *level == target_level {
                    *expanded = expand;
                    break;
                }
            }
        }
    }

    fn select_all_in_current_group(&mut self) {
        if let Some(selected_index) = self.selected_violation.selected() {
            let selected_item = self.flat_display_items.get(selected_index).cloned();
            if let Some(selected_item) = selected_item {
                match selected_item {
                    GroupItem::Group { name, level, .. } => {
                        // Selected item is a group - select all violations in this group
                        self.select_violations_in_group(&name, level);
                    }
                    GroupItem::Violation { .. } => {
                        // Selected item is a violation - find its parent group and select all in that group
                        if let Some(parent_group) =
                            self.find_parent_group_for_violation(selected_index)
                        {
                            self.select_violations_in_group(&parent_group.0, parent_group.1);
                        }
                    }
                    GroupItem::CleanFile { .. } => {
                        // Clean files don't participate in group selection
                    }
                }
            }
        }
    }

    fn deselect_all_in_current_group(&mut self) {
        if let Some(selected_index) = self.selected_violation.selected() {
            let selected_item = self.flat_display_items.get(selected_index).cloned();
            if let Some(selected_item) = selected_item {
                match selected_item {
                    GroupItem::Group { name, level, .. } => {
                        // Selected item is a group - deselect all violations in this group
                        self.deselect_violations_in_group(&name, level);
                    }
                    GroupItem::Violation { .. } => {
                        // Selected item is a violation - find its parent group and deselect all in that group
                        if let Some(parent_group) =
                            self.find_parent_group_for_violation(selected_index)
                        {
                            self.deselect_violations_in_group(&parent_group.0, parent_group.1);
                        }
                    }
                    GroupItem::CleanFile { .. } => {
                        // Clean files don't participate in group selection
                    }
                }
            }
        }
    }

    fn select_violations_in_group(&mut self, group_name: &str, group_level: usize) {
        let mut violations_to_select = HashSet::new();
        let mut inside_target_group = false;

        for item in &self.flat_display_items {
            match item {
                GroupItem::Group { name, level, .. } => {
                    if name == group_name && *level == group_level {
                        inside_target_group = true;
                    } else if *level <= group_level {
                        // We've reached another group at the same or higher level, stop
                        inside_target_group = false;
                    }
                }
                GroupItem::Violation { original_index, .. } => {
                    if inside_target_group {
                        violations_to_select.insert(*original_index);
                    }
                }
                GroupItem::CleanFile { .. } => {
                    // Clean files don't participate in selection
                }
            }
        }

        // Add the violations to the checked set
        for violation_index in violations_to_select {
            self.checked_violations.insert(violation_index);
        }
    }

    fn deselect_violations_in_group(&mut self, group_name: &str, group_level: usize) {
        let mut violations_to_deselect = Vec::new();
        let mut inside_target_group = false;

        for item in &self.flat_display_items {
            match item {
                GroupItem::Group { name, level, .. } => {
                    if name == group_name && *level == group_level {
                        inside_target_group = true;
                    } else if *level <= group_level {
                        // We've reached another group at the same or higher level, stop
                        inside_target_group = false;
                    }
                }
                GroupItem::Violation { original_index, .. } => {
                    if inside_target_group {
                        violations_to_deselect.push(*original_index);
                    }
                }
                GroupItem::CleanFile { .. } => {
                    // Clean files don't participate in selection
                }
            }
        }

        // Remove the violations from the checked set
        for violation_index in violations_to_deselect {
            self.checked_violations.remove(&violation_index);
        }
    }

    fn find_parent_group_for_violation(&self, violation_index: usize) -> Option<(String, usize)> {
        let mut current_group: Option<(String, usize)> = None;

        for (i, item) in self.flat_display_items.iter().enumerate() {
            if i == violation_index {
                return current_group;
            }

            match item {
                GroupItem::Group { name, level, .. } => {
                    current_group = Some((name.clone(), *level));
                }
                GroupItem::Violation { .. } => {
                    // Continue - we're still looking for our target violation
                }
                GroupItem::CleanFile { .. } => {
                    // Continue - clean files don't affect group hierarchy
                }
            }
        }

        None
    }

    fn scan_repository<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        use crate::analyze::prescan;
        use crate::files::ProjectSource;
        use crate::parser::CParser;

        // Reset cancellation flag
        self.scan_cancellation.store(false, Ordering::Relaxed);

        // Show progress dialog
        self.show_progress_dialog = true;

        self.violations.clear();
        self.suppressed_violations.clear();
        self.clean_files.clear();
        self.combined_violations.clear();

        // Pre-scan directories for cross-file context
        let mut context = if !self.directories.is_empty() {
            prescan::prescan_directories(&self.directories, None, true)?
        } else {
            crate::analyze::context::ProjectContext::new()
        };

        // Resolve #include directives against include search paths
        let project_source = ProjectSource::open(&self.repo_path)?;
        let c_files = project_source.get_c_files()?;

        if !self.include_paths.is_empty() {
            let mut project_roots: Vec<String> = vec![self.repo_path.clone()];
            project_roots.extend(self.directories.iter().cloned());
            let _ = prescan::resolve_includes(
                &c_files,
                &self.include_paths,
                &project_roots,
                &mut context,
                None,
                true,
            );
        }

        if context.has_cross_file_data() {
            for rule in self.registry.all_rules() {
                rule.set_project_context(&context);
            }
        }
        let total_files = c_files.len();
        let mut parser = CParser::new()?;

        self.progress_total_files = total_files;

        for (file_idx, file_path) in c_files.iter().enumerate() {
            // Check for cancellation before processing each file
            if self.scan_cancellation.load(Ordering::Relaxed) {
                break; // Exit early, keeping partial results
            }

            // Update progress state with full relative path
            self.progress_current_file = file_idx + 1;
            self.progress_file_path = file_path.clone();

            // Redraw the UI to show progress
            terminal.draw(|f| self.ui(f))?;

            // Poll for ESC key press with very short timeout
            if self.poll_esc_cancellation()? {
                break;
            }

            if let Ok((tree, source)) = parser.parse_file(file_path) {
                self.scan_parsed_file(terminal, file_path, &tree.root_node(), &source)?;
            }
        }

        // Hide progress dialog
        self.show_progress_dialog = false;

        // Update combined violations for toggle display
        self.update_combined_violations();

        self.update_display_violations();

        if !self.get_active_violations().is_empty() {
            self.selected_violation.select(Some(0));
        }

        // Update sorting after loading violations
        self.update_sort();

        Ok(())
    }

    /// Poll for an ESC keypress with a very short timeout, and if seen,
    /// set the cancellation flag. Returns whether cancellation was requested.
    fn poll_esc_cancellation(&self) -> Result<bool> {
        use std::time::Duration;
        if event::poll(Duration::from_millis(1))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Esc {
                    self.scan_cancellation.store(true, Ordering::Relaxed);
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Run all enabled rules against one already-parsed file, splitting
    /// results into active/suppressed violations, and record it as clean
    /// if no rule fired.
    fn scan_parsed_file<B: Backend>(
        &mut self,
        terminal: &mut Terminal<B>,
        file_path: &str,
        root_node: &Node,
        source: &str,
    ) -> Result<()> {
        // Extract suppressions from this file
        let mut suppression_manager = SuppressionManager::new();
        suppression_manager.extract_from_source(file_path, source);

        // Collect enabled rules to avoid borrow checker issues with terminal.draw
        let enabled_rules: Vec<(String, RuleConfig)> = self
            .manifest
            .enabled_rules()
            .map(|(id, config)| (id.clone(), config.clone()))
            .collect();

        let mut file_has_violations = false;
        for (rule_id, rule_config) in &enabled_rules {
            // Check for cancellation between rules
            if self.scan_cancellation.load(Ordering::Relaxed) {
                break;
            }

            // Update current rule being checked
            self.progress_rule_id = rule_id.to_string();

            // Redraw UI and poll for ESC key during rule checking for better responsiveness
            terminal.draw(|f| self.ui(f))?;
            if self.poll_esc_cancellation()? {
                break;
            }

            file_has_violations |= self.apply_rule_to_file(
                rule_id,
                rule_config,
                root_node,
                source,
                file_path,
                &suppression_manager,
            );
        }

        // If the file had no violations, add it to clean files
        if !file_has_violations {
            self.clean_files.push(file_path.to_string());
        }
        Ok(())
    }

    /// Run a single rule against a parsed file, sorting its violations into
    /// `self.violations` / `self.suppressed_violations`. Returns whether the
    /// rule produced any violations at all (suppressed or not).
    fn apply_rule_to_file(
        &mut self,
        rule_id: &str,
        rule_config: &RuleConfig,
        root_node: &Node,
        source: &str,
        file_path: &str,
        suppression_manager: &SuppressionManager,
    ) -> bool {
        let Some(rule) = self.registry.get_rule(rule_id) else {
            return false;
        };
        let mut file_violations = rule.check(root_node, source);
        for violation in &mut file_violations {
            violation.file_path = file_path.to_string();
            // Use config severity if specified, otherwise use rule's default severity
            violation.severity = rule_config
                .severity
                .clone()
                .unwrap_or_else(|| rule.severity());
        }

        let has_violations = !file_violations.is_empty();
        for violation in file_violations {
            if suppression_manager
                .should_suppress(
                    file_path,
                    rule_id,
                    violation.line,
                    source,
                    &violation.message,
                )
                .is_some()
            {
                // This violation is suppressed
                self.suppressed_violations.push(violation);
            } else {
                // This violation is active
                self.violations.push(violation);
            }
        }
        has_violations
    }

    fn export_violations(&self, path: &PathBuf) -> Result<()> {
        if let Some(extension) = path.extension() {
            match extension.to_str() {
                Some("xlsx") => self.write_violations_to_excel(path),
                Some("csv") => self.write_violations_to_csv(path),
                _ => {
                    // Default to Excel for unknown extensions
                    self.write_violations_to_excel(path)
                }
            }
        } else {
            // No extension, default to Excel
            self.write_violations_to_excel(path)
        }
    }

    fn write_violations_to_csv(&self, path: &PathBuf) -> Result<()> {
        use csv::Writer;

        let mut writer = Writer::from_path(path)?;

        // Write CSV headers
        writer.write_record([
            "Title",
            "Description",
            "Work Item Type",
            "State",
            "Severity",
            "Priority",
        ])?;

        // Write selected violations only
        for &index in &self.checked_violations {
            if let Some(violation) = self.violations.get(index) {
                let file_hash = self.calculate_file_hash(&violation.file_path)?;
                let relative_path = self.get_relative_path(&violation.file_path);

                let title = format!(
                    "{}:{}:{} version:{}",
                    violation.rule_id, relative_path, violation.line, file_hash
                );

                let code_snippet = self.get_code_snippet(&violation.file_path, violation.line)?;
                let rule_description = self.get_rule_description(&violation.rule_id);
                let description = format!(
                    "{} - {}: {}",
                    violation.rule_id, rule_description, code_snippet
                );

                writer.write_record([
                    &title,
                    &description,
                    "Bug",
                    "Proposed",
                    "1 - Critical",
                    "1",
                ])?;
            }
        }

        writer.flush()?;
        Ok(())
    }

    fn write_violations_to_excel(&self, path: &PathBuf) -> Result<()> {
        use rust_xlsxwriter::{Color as XlsxColor, Format, Workbook};

        let mut workbook = Workbook::new();
        let worksheet = workbook.add_worksheet();

        // Create header format
        let header_format = Format::new()
            .set_bold()
            .set_background_color(XlsxColor::RGB(0xD9D9D9));

        // Write headers
        let headers = [
            "Title",
            "Description",
            "Work Item Type",
            "State",
            "Severity",
            "Priority",
        ];

        for (col, header) in headers.iter().enumerate() {
            worksheet.write_string_with_format(0, col as u16, *header, &header_format)?;
        }

        // Write selected violations
        let mut row = 1;
        for &index in &self.checked_violations {
            if let Some(violation) = self.violations.get(index) {
                let file_hash = self.calculate_file_hash(&violation.file_path)?;
                let relative_path = self.get_relative_path(&violation.file_path);

                let title = format!(
                    "{}:{}:{} version:{}",
                    violation.rule_id, relative_path, violation.line, file_hash
                );

                let code_snippet = self.get_code_snippet(&violation.file_path, violation.line)?;
                let rule_description = self.get_rule_description(&violation.rule_id);
                let description = format!(
                    "{} - {}: {}",
                    violation.rule_id, rule_description, code_snippet
                );

                worksheet.write_string(row, 0, &title)?;
                worksheet.write_string(row, 1, &description)?;
                worksheet.write_string(row, 2, "Bug")?;
                worksheet.write_string(row, 3, "Proposed")?;
                worksheet.write_string(row, 4, "1 - Critical")?;
                worksheet.write_string(row, 5, "1")?;

                row += 1;
            }
        }

        // Auto-fit columns
        worksheet.autofit();

        workbook.save(path)?;
        Ok(())
    }

    fn calculate_file_hash(&self, file_path: &str) -> Result<String> {
        let content = fs::read(file_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let result = hasher.finalize();
        Ok(format!("{:x}", result)[..8].to_string())
    }

    fn get_code_snippet(&self, file_path: &str, line_number: usize) -> Result<String> {
        let content = fs::read_to_string(file_path)?;
        let lines: Vec<&str> = content.lines().collect();

        if line_number > 0 && line_number <= lines.len() {
            let line = lines[line_number - 1].trim();
            Ok(line.to_string())
        } else {
            Ok("(line not found)".to_string())
        }
    }

    fn get_rule_description(&self, rule_id: &str) -> String {
        if let Some(rule) = self.registry.get_rule(rule_id) {
            rule.description().to_string()
        } else {
            "Unknown rule".to_string()
        }
    }

    fn get_relative_path(&self, file_path: &str) -> String {
        file_path.to_string()
    }

    // Suppression functionality
    fn initiate_suppression(&mut self) {
        // Check for uncommitted changes
        if let Ok(uncommitted) = self.check_git_status() {
            self.uncommitted_files = uncommitted;
        } else {
            self.uncommitted_files.clear();
        }

        // Generate suppression summary
        self.suppression_summary = self.generate_suppression_summary();

        // Show the confirmation dialog
        self.show_suppression_dialog = true;
    }

    fn check_git_status(&self) -> Result<Vec<String>> {
        use std::process::Command;

        let output = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&self.repo_path)
            .output()
            .context("Failed to run git status")?;

        let status = String::from_utf8_lossy(&output.stdout);
        let mut uncommitted_files = Vec::new();

        for line in status.lines() {
            if !line.is_empty() {
                let file_path = &line[3..]; // Skip the status flags
                uncommitted_files.push(file_path.to_string());
            }
        }

        Ok(uncommitted_files)
    }

    fn generate_suppression_summary(&self) -> Vec<SuppressionSummary> {
        let mut summary_map: HashMap<String, Vec<ViolationSuppression>> = HashMap::new();

        for &index in &self.checked_violations {
            if let Some(violation) = self.violations.get(index) {
                // Read the source file to get code context
                if let Ok(source) = fs::read_to_string(&violation.file_path) {
                    let code_lines: Vec<&str> = source.lines().collect();

                    // Get the code preview (handle potential out-of-bounds)
                    let code_preview = if violation.line > 0 && violation.line <= code_lines.len() {
                        code_lines[violation.line - 1].trim().to_string()
                    } else {
                        "(line not found)".to_string()
                    };

                    // Calculate hash for the violation
                    let hash = SuppressionManager::calculate_suppression_hash(
                        &violation.rule_id,
                        &code_preview,
                    );

                    let violation_suppression = ViolationSuppression {
                        rule_id: violation.rule_id.clone(),
                        line: violation.line,
                        code_preview,
                        hash,
                    };

                    summary_map
                        .entry(violation.file_path.clone())
                        .or_default()
                        .push(violation_suppression);
                }
            }
        }

        summary_map
            .into_iter()
            .map(|(file_path, violations)| SuppressionSummary {
                file_path,
                violations,
            })
            .collect()
    }

    fn apply_suppressions(&self) -> Result<()> {
        for summary in &self.suppression_summary {
            self.add_suppressions_to_file(&summary.file_path, &summary.violations)?;
        }
        Ok(())
    }

    fn add_suppressions_to_file(
        &self,
        file_path: &str,
        violations: &[ViolationSuppression],
    ) -> Result<()> {
        // Read the current file content
        let content = fs::read_to_string(file_path)?;
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

        // Sort violations by line number in reverse order to avoid index shifting
        let mut sorted_violations = violations.to_vec();
        sorted_violations.sort_by_key(|v| std::cmp::Reverse(v.line));

        // Get user information
        let user_info = self.get_user_info();
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

        for violation in sorted_violations {
            if violation.line > 0 && violation.line <= lines.len() {
                let suppression_comment = format!(
                    "// SQC-SUPPRESS: {} HASH:{} JUSTIFICATION: \"Suppressed by {} on {}\"",
                    violation.rule_id, violation.hash, user_info, timestamp
                );

                // Insert the suppression comment before the violation line
                lines.insert(violation.line - 1, suppression_comment);
            }
        }

        // Write the modified content back to the file
        let new_content = lines.join("\n") + "\n";
        fs::write(file_path, new_content)?;

        Ok(())
    }

    fn get_user_info(&self) -> String {
        // Try to get user from git config first
        if let Ok(git_user) = self.get_git_user_email() {
            return git_user;
        }

        // Fallback to system user
        if let Ok(username) = std::env::var("USER") {
            return username;
        }

        // Last resort
        "unknown-user".to_string()
    }

    fn get_git_user_email(&self) -> Result<String> {
        use std::process::Command;

        let output = Command::new("git")
            .args(["config", "user.email"])
            .current_dir(&self.repo_path)
            .output()
            .context("Failed to get git user email")?;

        if output.status.success() {
            let email = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !email.is_empty() {
                return Ok(email);
            }
        }

        // Try git user.name as fallback
        let output = Command::new("git")
            .args(["config", "user.name"])
            .current_dir(&self.repo_path)
            .output()
            .context("Failed to get git user name")?;

        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() {
                return Ok(name);
            }
        }

        Err(anyhow::anyhow!("No git user configured"))
    }

    fn render_suppression_dialog(&mut self, f: &mut Frame) {
        use ratatui::layout::Rect;

        // Create a centered popup
        let area = f.area();
        let popup_area = Rect {
            x: area.width / 6,
            y: area.height / 6,
            width: area.width * 2 / 3,
            height: area.height * 2 / 3,
        };

        // Clear the background
        f.render_widget(Clear, popup_area);

        // Create the content
        let mut content_lines = vec![Line::from("Suppression Confirmation"), Line::from("")];

        // Add warning about uncommitted files if any
        if !self.uncommitted_files.is_empty() {
            content_lines.push(Line::from(vec![
                Span::styled("WARNING: ", Style::default().fg(Color::Red)),
                Span::raw("Uncommitted changes detected in:"),
            ]));

            for file in &self.uncommitted_files {
                content_lines.push(Line::from(format!("  - {}", file)));
            }

            content_lines.push(Line::from(""));
            content_lines.push(Line::from(
                "These files may have conflicts with suppression comments.",
            ));
            content_lines.push(Line::from(""));
        }

        // Add suppression summary
        content_lines.push(Line::from("The following violations will be suppressed:"));
        content_lines.push(Line::from(""));

        for summary in &self.suppression_summary {
            content_lines.push(Line::from(format!("File: {}", summary.file_path)));

            for violation in &summary.violations {
                content_lines.push(Line::from(format!(
                    "  - Line {}: {} ({})",
                    violation.line,
                    violation.rule_id,
                    violation.code_preview.chars().take(60).collect::<String>()
                )));
            }

            content_lines.push(Line::from(""));
        }

        content_lines.push(Line::from(""));
        content_lines.push(Line::from(vec![
            Span::styled("Press ", Style::default().fg(Color::White)),
            Span::styled("Enter/y", Style::default().fg(Color::Green)),
            Span::styled(" to confirm, ", Style::default().fg(Color::White)),
            Span::styled("Esc/n", Style::default().fg(Color::Red)),
            Span::styled(" to cancel", Style::default().fg(Color::White)),
        ]));

        let popup = Paragraph::new(content_lines)
            .block(
                Block::default()
                    .title("Generate Suppression Comments")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            )
            .wrap(ratatui::widgets::Wrap { trim: true });

        f.render_widget(popup, popup_area);
    }

    fn render_progress_dialog(&mut self, f: &mut Frame) {
        let area = f.area();
        let popup_area = Rect {
            x: area.width / 4,
            y: area.height / 2 - 4,
            width: area.width / 2,
            height: 8,
        };

        // Clear the background
        f.render_widget(Clear, popup_area);

        // Render popup border
        let popup_block = Block::default()
            .borders(Borders::ALL)
            .title("Scanning Repository...")
            .border_style(Style::default().fg(Color::Yellow));

        f.render_widget(popup_block, popup_area);

        let inner_area = Rect {
            x: popup_area.x + 1,
            y: popup_area.y + 1,
            width: popup_area.width - 2,
            height: popup_area.height - 2,
        };

        let dialog_text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("File: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!(
                        "{} of {}",
                        self.progress_current_file, self.progress_total_files
                    ),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(&self.progress_file_path, Style::default().fg(Color::White)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Checking: ", Style::default().fg(Color::Cyan)),
                Span::styled(&self.progress_rule_id, Style::default().fg(Color::Green)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Press ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "ESC",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" to cancel...", Style::default().fg(Color::Gray)),
            ]),
        ];

        let dialog_paragraph = Paragraph::new(dialog_text)
            .style(Style::default().fg(Color::White))
            .alignment(Alignment::Left);

        f.render_widget(dialog_paragraph, inner_area);
    }

    fn update_display_violations(&mut self) {
        // This method is called when the show_suppressed toggle changes
        // We need to rebuild the display items to reflect the new violation list
        self.update_sort();
    }

    fn get_active_violations(&self) -> &Vec<RuleViolation> {
        if self.show_suppressed {
            // Show combined active and suppressed violations
            &self.combined_violations
        } else {
            // Show only non-suppressed violations
            &self.violations
        }
    }

    fn update_combined_violations(&mut self) {
        // Create combined list with active violations first, then suppressed
        self.combined_violations.clear();
        self.combined_violations
            .extend(self.violations.iter().cloned());
        self.combined_violations
            .extend(self.suppressed_violations.iter().cloned());

        // Sort the combined list according to current sort mode
        match self.sort_mode {
            SortMode::Default => {
                // Keep original order - no additional sorting needed
            }
            SortMode::ViolationId => {
                self.combined_violations.sort_by(|a, b| {
                    if self.sort_ascending {
                        a.rule_id.cmp(&b.rule_id)
                    } else {
                        b.rule_id.cmp(&a.rule_id)
                    }
                });
            }
            SortMode::FilePath => {
                let sort_ascending = self.sort_ascending;
                self.combined_violations.sort_by(|a, b| {
                    if sort_ascending {
                        a.file_path.cmp(&b.file_path)
                    } else {
                        b.file_path.cmp(&a.file_path)
                    }
                });
            }
            SortMode::FileName => {
                self.combined_violations.sort_by(|a, b| {
                    let name_a = std::path::Path::new(&a.file_path)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    let name_b = std::path::Path::new(&b.file_path)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    if self.sort_ascending {
                        name_a.cmp(&name_b)
                    } else {
                        name_b.cmp(&name_a)
                    }
                });
            }
        }
    }

    fn is_violation_suppressed(&self, violation: &RuleViolation) -> bool {
        // Check if this violation exists in the suppressed_violations list
        self.suppressed_violations.iter().any(|suppressed| {
            suppressed.rule_id == violation.rule_id
                && suppressed.file_path == violation.file_path
                && suppressed.line == violation.line
                && suppressed.column == violation.column
        })
    }
}
