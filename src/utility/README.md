# Utility Module

This module provides common helper functions and utilities used throughout the aurora-lint codebase.

## Purpose

The utility module centralizes frequently-used functionality to:
- Reduce code duplication
- Maintain consistency across modules
- Provide optimized implementations
- Simplify complex operations

## Common Utilities

### String Manipulation
- **`trim_code_snippet()`** - Formats code snippets for display
- **`escape_special_chars()`** - Escapes characters for safe output
- **`truncate_with_ellipsis()`** - Intelligently truncates long strings
- **`normalize_line_endings()`** - Standardizes line endings across platforms

### Path Operations
- **`canonicalize_path()`** - Resolves to absolute canonical paths
- **`relative_path_from()`** - Computes relative paths for display
- **`is_source_file()`** - Validates file extensions
- **`ensure_directory_exists()`** - Creates directories recursively

### Code Analysis Helpers
- **`extract_line_context()`** - Gets surrounding code lines
- **`calculate_column_position()`** - Computes column from byte offset
- **`get_function_name()`** - Extracts enclosing function name
- **`find_matching_brace()`** - Locates paired delimiters

### Hashing and Checksums
- **`calculate_sha256()`** - Generates SHA-256 hashes for suppressions
- **`generate_violation_hash()`** - Creates unique violation identifiers
- **`verify_file_checksum()`** - Validates file integrity

### Formatting and Display
- **`format_severity()`** - Colorizes severity levels
- **`format_file_location()`** - Creates file:line:column strings
- **`format_rule_id()`** - Standardizes rule ID display
- **`create_progress_bar()`** - Terminal progress indicators

### Time and Date
- **`format_timestamp()`** - Human-readable timestamps
- **`parse_iso_date()`** - ISO 8601 date parsing
- **`calculate_duration()`** - Execution time measurement

## Error Handling Utilities

### Custom Error Types
```rust
pub enum UtilityError {
    PathError(String),
    ParseError(String),
    ValidationError(String),
}
```

### Error Context
- **`with_context()`** - Adds contextual information to errors
- **`map_io_error()`** - Converts I/O errors with context
- **`chain_errors()`** - Creates error chains for debugging

## Performance Utilities

### Caching
- **`memoize()`** - Function result caching
- **`lru_cache()`** - Least recently used cache
- **`file_cache()`** - Disk-based caching

### Parallelization
- **`parallel_map()`** - Parallel processing with rayon
- **`chunk_process()`** - Batch processing for large datasets
- **`thread_pool_execute()`** - Managed thread pool operations

## Validation Functions

### Input Validation
- **`validate_manifest()`** - Checks manifest structure
- **`validate_rule_id()`** - Verifies CERT rule format
- **`validate_file_path()`** - Ensures path validity
- **`validate_severity()`** - Checks severity values

### Sanitization
- **`sanitize_user_input()`** - Cleans user-provided data
- **`sanitize_file_path()`** - Removes dangerous path components
- **`sanitize_regex()`** - Escapes regex special characters

## Configuration Helpers

### Environment
- **`get_config_dir()`** - Locates configuration directory
- **`load_env_vars()`** - Reads environment variables
- **`detect_terminal_size()`** - Gets terminal dimensions

### Defaults
- **`default_manifest_path()`** - Standard manifest location
- **`default_suppression_file()`** - Standard suppression file
- **`default_export_format()`** - Preferred export format

## Testing Utilities

### Test Helpers
- **`create_temp_project()`** - Temporary test directories
- **`write_test_file()`** - Creates test C files
- **`assert_violation_eq()`** - Custom assertion for violations
- **`mock_manifest()`** - Test manifest generation

## Platform Compatibility

### Cross-Platform Support
- **`normalize_path_separator()`** - OS-agnostic paths
- **`get_home_directory()`** - User home directory
- **`is_windows()`** - Platform detection
- **`shell_escape()`** - Platform-specific escaping

## Constants

```rust
pub const MAX_LINE_LENGTH: usize = 120;
pub const DEFAULT_CONTEXT_LINES: usize = 3;
pub const VIOLATION_HASH_LENGTH: usize = 64;
pub const MAX_PATH_DISPLAY: usize = 80;
```

## Usage Examples

```rust
use utility::*;

// Format file location
let location = format_file_location("src/main.c", 42, 15);
// Output: "src/main.c:42:15"

// Calculate hash
let hash = calculate_sha256(b"violation data");

// Extract code context
let context = extract_line_context(source, line_num, 2);
```

## Dependencies

Internal utilities rely on:
- `sha2` - Cryptographic hashing
- `chrono` - Date/time operations
- `regex` - Pattern matching
- `anyhow` - Error handling