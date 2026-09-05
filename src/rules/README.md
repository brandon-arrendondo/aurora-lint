# Rules Module

This module contains the implementation of all CERT C security rules that aurora-lint checks for.

## Architecture

### Core Components

- **`mod.rs`** - Defines the `CertRule` trait, rule registry, and violation reporting structures
- **`cert_c/`** - Contains individual implementations of CERT C rules organized by category

## Rule Categories

### Array Bounds (ARR)
- **ARR30-C** - Do not form or use out-of-bounds pointers or array subscripts
- **ARR32-C** - Ensure size arguments for variable-length arrays are in a valid range
- **ARR36-C** - Do not subtract or compare two pointers that do not refer to the same array
- **ARR37-C** - Do not add or subtract an integer to a pointer to a non-array object
- **ARR38-C** - Guarantee that library functions do not form invalid pointers
- **ARR39-C** - Do not add or subtract a scaled integer to a pointer

### Declarations and Initialization (DCL)
- **DCL00-C** - Const-qualify immutable objects

### Expressions (EXP)
- **EXP33-C** - Do not read uninitialized memory

### Integers (INT)
- **INT30-C** - Ensure that unsigned integer operations do not wrap

### Memory Management (MEM)
- **MEM30-C** - Do not access freed memory

### Preprocessor (PRE)
- **PRE30-C** - Do not create a universal character name through concatenation
- **PRE31-C** - Avoid side effects in arguments to unsafe macros
- **PRE32-C** - Do not use preprocessor directives in invocations of function-like macros

### Characters and Strings (STR)
- **STR31-C** - Guarantee that storage for strings has sufficient space

## CertRule Trait

Every rule implements the following trait:

```rust
pub trait CertRule {
    fn rule_id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation>;
}
```

## Adding New Rules

1. Create a new file in `cert_c/` following the naming pattern: `{category}{number}_c.rs`
2. Implement the `CertRule` trait for your rule struct
3. Add the rule to the registry in `cert_c/mod.rs`
4. Include appropriate test cases
5. Update the manifest template with rule metadata

## Violation Structure

Each violation contains:
- `rule_id` - CERT rule identifier
- `file` - Path to the file containing the violation
- `line` - Line number where violation occurs
- `column` - Column position
- `message` - Descriptive error message
- `severity` - High/Medium/Low based on security impact
- `code_snippet` - Relevant code excerpt

## Testing

Each rule should include comprehensive tests covering:
- True positive cases
- False negative prevention
- Edge cases and boundary conditions
- Performance with large code files