# Analyze Module

This module contains the core analysis engine that orchestrates the security scanning process and manages violation suppression.

## Components

### `mod.rs` - Analysis Orchestration
The main analysis module that coordinates:
- File discovery and filtering
- C code parsing with tree-sitter
- Rule execution across the AST
- Violation aggregation and deduplication
- Integration with suppression system

### `suppression.rs` - Violation Suppression System
Implements SHA-256 based suppression management:
- Generation of unique hashes for violations
- Loading suppression files (`suppress.toml`, falling back to the legacy `.sqc-suppress.toml` name)
- Filtering of suppressed violations from results
- Audit trail for suppression reasons

## Analysis Pipeline

1. **Project Initialization**
   - Load manifest configuration
   - Discover C source files (.c, .h)
   - Filter based on gitignore rules

2. **File Processing**
   - Parse each C file into an AST using tree-sitter
   - Walk the AST nodes recursively

3. **Rule Application**
   - Apply each enabled CERT rule to AST nodes
   - Collect violations with context information
   - Calculate severity based on rule configuration

4. **Suppression Filtering**
   - Load suppression file if exists
   - Generate SHA-256 hash for each violation
   - Filter out matching suppressed violations

5. **Result Aggregation**
   - Deduplicate violations
   - Sort by severity and location
   - Prepare for UI display or export

## Key Functions

### `analyze_project()`
Main entry point that:
- Accepts project path and manifest
- Returns vector of violations
- Handles errors gracefully with context

### `handle_generate_suppression()`
Prints ready-to-paste suppression snippets for a `file:line:rule` spec:
- The unified inline comment (`tools:suppress sqc:RULE HASH:... JUSTIFICATION:"..."`)
- The legacy inline comment (`SQC-SUPPRESS: RULE HASH:... JUSTIFICATION: "..."`)
- A `suppress.toml` `[[suppress]]` entry, for read-only codebases

### `apply_suppressions()`
Filters violations by:
- Computing SHA-256 hash from violation data
- Matching against suppression database
- Preserving non-suppressed violations

## Suppression File Format

`suppress.toml` — the shared, all-tools file from
`lang_parsing_substrate/docs/unified-config-spec.md`. `tool` scopes each
entry to `"sqc"` or the wildcard `"*"`; `rule_glob`/`function_prefix` are
sqc-specific extensions beyond the base spec.

```toml
# Hash-matched: exact code match, tamper-detected.
[[suppress]]
name          = "example-arr30"
tool          = "sqc"
file          = "src/example.c"
rule          = "ARR30-C"
hash          = "a1b2c3d4e5f6..."
justification = "Bounds check performed in calling function"

# Wildcard: no hash — matches by file_glob/rule/rule_glob/function_prefix (ANDed).
[[suppress]]
name          = "vendor-dcl"
tool          = "sqc"
file_glob     = "src/vendor/**"
rule_glob     = "DCL*"
justification = "Vendor code"
```

## Performance Considerations

- Tree-sitter provides incremental parsing for efficiency
- Rules are applied in a single AST traversal
- Suppression lookup uses HashMap for O(1) access
- File I/O is minimized through caching

## Error Handling

The module uses `anyhow::Result` for error propagation with contextual information:
- File access errors
- Parse failures
- Rule execution errors
- Suppression file corruption

## Integration Points

- **Parser Module** - For C code AST generation
- **Rules Module** - For CERT rule execution
- **Manifest Module** - For configuration loading
- **Files Module** - For source file discovery