# Files Module

This module manages file system operations, source file discovery, and Git repository integration for the aurora-lint analyzer.

## Core Functionality

### ProjectSource Enum
Represents the source of files to analyze:
- **Directory** - Local file system directory
- **GitRepository** - Git repository (local or cloned)

### File Discovery
Intelligent C source file discovery with:
- Recursive directory traversal
- Git repository awareness
- `.gitignore` respect
- File extension filtering (.c, .h)
- Symlink handling

## Key Components

### `discover_c_files()`
Main file discovery function that:
- Accepts a path (directory or repo)
- Returns vector of C source file paths
- Filters out build artifacts and dependencies
- Respects version control ignore rules

### `is_c_source_file()`
File validation that checks:
- File extension (.c, .h, .cpp, .hpp)
- MIME type verification (optional)
- Binary vs text detection

### Git Integration
Repository operations including:
- Repository detection
- Working directory identification
- Branch information retrieval
- Staged/unstaged file differentiation

## File Filtering Rules

### Included
- `*.c` - C source files
- `*.h` - C header files
- Files in source directories

### Excluded
- Build directories (`target/`, `build/`, `obj/`)
- Dependencies (`vendor/`, `node_modules/`)
- Generated files (`*.o`, `*.a`, `*.so`)
- Hidden files and directories (`.git/`, `.vscode/`)
- Backup files (`*.bak`, `*~`)

## Usage Patterns

```rust
// Analyze current directory
let files = discover_c_files(".")?;

// Analyze specific project
let files = discover_c_files("/path/to/project")?;

// Filter by specific patterns
let headers = files.iter()
    .filter(|f| f.ends_with(".h"))
    .collect();
```

## Performance Optimizations

- Parallel directory traversal with rayon
- Early termination for ignored paths
- Caching of gitignore patterns
- Minimal stat calls

## Error Handling

Graceful handling of:
- Permission denied errors
- Broken symlinks
- Invalid UTF-8 paths
- Missing directories
- Corrupted git repositories

## Integration with Git

### Git-Aware Features
- Analyze only tracked files
- Exclude gitignored files
- Support for submodules
- Worktree compatibility

### Repository Information
Extracts and provides:
- Current branch name
- Commit hash
- Modified file list
- Repository root path

## Path Handling

- Canonical path resolution
- Cross-platform path normalization
- Relative path display
- UTF-8 path encoding

## Dependencies

- `walkdir` - Efficient recursive directory traversal
- `git2` - Git repository operations
- `std::path` - Path manipulation
- `regex` - Pattern matching for filters

## Configuration

File discovery behavior can be customized through:
- Include/exclude patterns
- Maximum depth limits
- Follow symlinks option
- Case sensitivity settings

## Future Improvements

- Incremental file scanning
- File change detection
- Custom file type support
- Integration with build systems