# Parser Module

This module provides C/C++ code parsing capabilities using tree-sitter, enabling syntax-aware analysis of source code.

## Overview

The parser module leverages tree-sitter's incremental parsing to:
- Generate Abstract Syntax Trees (AST) from C code
- Enable efficient traversal of code structures
- Support incremental updates for large files
- Provide error-tolerant parsing

## Core Components

### Parser Initialization
```rust
pub fn init_parser() -> Parser {
    let mut parser = Parser::new();
    parser.set_language(crate::parser::c_language())
        .expect("Error loading C grammar");
    parser
}
```

### Parsing Pipeline

1. **Source Loading** - Read C source file into memory
2. **Tree Generation** - Parse source into AST
3. **Node Traversal** - Walk tree for analysis
4. **Query Execution** - Run pattern queries
5. **Error Recovery** - Handle syntax errors gracefully

## Key Functions

### `parse_c_file()`
Main parsing entry point:
- Accepts file path or source string
- Returns tree-sitter Tree
- Handles encoding issues
- Reports parse errors

### `traverse_ast()`
Recursive AST traversal:
- Visits all nodes depth-first
- Applies visitor pattern
- Collects relevant nodes
- Maintains parent context

### `query_nodes()`
Pattern-based node selection:
- S-expression queries
- Capture groups
- Predicate filtering
- Performance optimization

### `get_node_text()`
Extract source text from nodes:
- Handles byte ranges
- UTF-8 decoding
- Whitespace preservation
- Comment inclusion

## AST Node Types

### Common C Nodes
- `translation_unit` - Root of C file
- `function_definition` - Function declarations
- `compound_statement` - Code blocks
- `declaration` - Variable declarations
- `expression_statement` - Expressions
- `if_statement` - Conditional branches
- `for_statement` - For loops
- `while_statement` - While loops
- `return_statement` - Return statements
- `call_expression` - Function calls
- `binary_expression` - Binary operations
- `identifier` - Variable/function names
- `string_literal` - String constants
- `number_literal` - Numeric constants

### Preprocessor Nodes
- `preproc_include` - Include directives
- `preproc_define` - Macro definitions
- `preproc_ifdef` - Conditional compilation
- `preproc_function_def` - Function-like macros

## Tree-Sitter Queries

### Query Syntax
```scm
; Find all array subscript expressions
(subscript_expression
  array: (identifier) @array
  index: (_) @index)

; Find potential buffer overflows
(call_expression
  function: (identifier) @func
  (#match? @func "^(strcpy|strcat|gets)$"))
```

### Using Queries
```rust
let query = Query::new(
    crate::parser::c_language(),
    "(binary_expression) @expr"
)?;

let mut cursor = QueryCursor::new();
let matches = cursor.matches(&query, root_node, source.as_bytes());
```

## Error Handling

### Parse Errors
- Syntax errors in source code
- Incomplete statements
- Invalid constructs
- Recovery strategies

### Error Information
```rust
pub struct ParseError {
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub severity: ErrorSeverity,
}
```

## Performance Optimization

### Incremental Parsing
- Reuse unchanged subtrees
- Minimal reparsing on edits
- Efficient for large files
- Real-time analysis support

### Memory Management
- Tree lifecycle management
- Node reference counting
- Buffer pooling
- Cache strategies

## Integration Points

- **Rules Module** - Provides AST nodes for rule checking
- **Analyze Module** - Orchestrates parsing workflow
- **UI Module** - Displays parse progress
- **Utility Module** - Common parsing helpers

## Advanced Features

### Custom Predicates
```rust
// Register custom predicates for queries
query.add_predicate("is_unsafe", |node| {
    unsafe_functions.contains(node.text())
});
```

### Node Utilities
- **`get_parent_function()`** - Find enclosing function
- **`get_siblings()`** - Get sibling nodes
- **`find_ancestor()`** - Search up the tree
- **`get_children_by_type()`** - Filter child nodes

### Source Locations
- **`node_to_range()`** - Convert to line/column
- **`point_to_offset()`** - Byte offset calculation
- **`get_line_content()`** - Extract line text

## Debugging Support

### AST Visualization
```rust
pub fn print_ast(node: Node, source: &str, depth: usize) {
    let indent = "  ".repeat(depth);
    println!("{}{} [{}]", indent, node.kind(),
             node.start_position()..node.end_position());
    // Recurse for children
}
```

### Query Testing
- Interactive query REPL
- Query validation
- Performance profiling
- Match highlighting

## Language Support

While primarily for C, the parser also handles:
- C++ (subset)
- Objective-C (basic)
- Header files (.h)
- Inline assembly (limited)

## Dependencies

- `tree-sitter` (0.22) - Core parsing library
- `tree-sitter-c` (0.21) - C language grammar
- `regex` - Pattern matching
- `once_cell` - Lazy initialization