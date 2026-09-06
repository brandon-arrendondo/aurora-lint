# aurora-lint Source Code

This directory contains the core implementation of the aurora-lint CERT C compliance checker.

## Module Structure

- **`main.rs`** - Application entry point, CLI argument parsing, and execution orchestration
- **`prelude.rs`** - Common imports, type aliases, and shared definitions used throughout the codebase
- **`analyze/`** - Core analysis engine for processing C code and managing violations
- **`export/`** - Export functionality for generating reports in CSV and Excel formats
- **`files/`** - File system operations and Git repository integration
- **`manifest/`** - TOML-based rule configuration and manifest management
- **`parser/`** - Tree-sitter based C code parsing and AST traversal
- **`rules/`** - CERT C rule implementations and rule registry
- **`ui/`** - Interactive terminal user interface built with ratatui
- **`utility/`** - Helper functions and common utilities

## Key Components

### Analysis Pipeline
1. **File Discovery** - Locates C source files in the target directory or Git repository
2. **Parsing** - Uses tree-sitter to parse C code into an AST
3. **Rule Checking** - Applies enabled CERT C rules to detect violations
4. **Suppression** - Filters out suppressed violations based on SHA-256 hashes
5. **Reporting** - Displays results in UI or exports to various formats

### Rule System
Rules are implemented as structs that implement the `CertRule` trait, providing:
- Rule ID (e.g., "ARR30-C")
- Description of the security issue
- AST-based checking logic
- Violation reporting

### Error Handling
The codebase uses `anyhow::Result` for error propagation with contextual error messages throughout the application.

## Development

To add new functionality:
1. New CERT rules go in `rules/cert_c/`
2. UI components are added to `ui/mod.rs`
3. Export formats are implemented in `export/mod.rs`
4. Analysis logic extensions go in `analyze/mod.rs`