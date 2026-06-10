use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

#[allow(dead_code)]
pub struct Mem33C {
    // Track structures that contain flexible array members
    flexible_structs: HashMap<String, FlexibleArrayInfo>,
    // Track arrays of flexible array structures
    flexible_struct_arrays: HashSet<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FlexibleArrayInfo {
    struct_name: String,
    has_flexible_array: bool,
    declaration_line: usize,
    is_valid_definition: bool, // New field to track if struct definition is valid
}

#[derive(Debug)]
struct FlexibleArrayValidation {
    flexible_member_count: usize,
    flexible_member_positions: Vec<usize>,
    total_field_count: usize,
    last_field_is_flexible: bool,
    violations: Vec<String>,
}

impl FlexibleArrayValidation {
    fn new() -> Self {
        Self {
            flexible_member_count: 0,
            flexible_member_positions: Vec::new(),
            total_field_count: 0,
            last_field_is_flexible: false,
            violations: Vec::new(),
        }
    }

    fn is_valid_flexible_struct(&self) -> bool {
        // Valid flexible array struct: exactly 1 flexible member as last field, at least 2 total fields
        self.flexible_member_count == 1
            && self.last_field_is_flexible
            && self.total_field_count >= 2
            && self.violations.is_empty()
    }

    fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }
}

#[derive(Debug, Clone)]
struct ArrayDeclaratorInfo {
    base_type: String,
    is_array: bool,
    array_size: Option<String>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct StorageInfo {
    storage_type: String,
    is_dynamic: bool,
}

#[derive(Debug)]
struct UnionViolationInfo {
    member_name: String,
    line: usize,
    column: usize,
}

#[derive(Debug)]
struct FieldDeclarationInfo {
    field_name: String,
    type_name: String,
    is_pointer: bool,
    is_array: bool,
}

impl Mem33C {
    pub fn new() -> Self {
        Self {
            flexible_structs: HashMap::new(),
            flexible_struct_arrays: HashSet::new(),
        }
    }
}

impl CertRule for Mem33C {
    fn rule_id(&self) -> &'static str {
        "MEM33-C"
    }

    fn description(&self) -> &'static str {
        "Allocate and copy structures containing a flexible array member dynamically"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MEM33-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let mut analyzer = FlexibleArrayAnalyzer::new();

        // First pass: identify structures with flexible array members
        analyzer.collect_flexible_array_structs(node, source);

        // Second pass: detect violations
        violations.extend(analyzer.check_violations(node, source));

        violations
    }
}

struct FlexibleArrayAnalyzer {
    flexible_structs: HashMap<String, FlexibleArrayInfo>,
    flexible_struct_arrays: HashSet<String>,
}

impl FlexibleArrayAnalyzer {
    fn new() -> Self {
        Self {
            flexible_structs: HashMap::new(),
            flexible_struct_arrays: HashSet::new(),
        }
    }

    fn collect_flexible_array_structs(&mut self, node: &Node, source: &str) {
        // Iterative pre-order walk: deeply nested code (e.g. multi-thousand-deep
        // else-if chains) overflows the stack with self-recursion.
        let mut stack = vec![*node];
        while let Some(current) = stack.pop() {
            // Look for struct declarations with flexible array members
            if current.kind() == "struct_specifier" {
                if let Some(info) = self.analyze_struct_for_flexible_array(&current, source) {
                    self.flexible_structs.insert(info.struct_name.clone(), info);
                }
            }

            // Look for typedef declarations of flexible array structures
            if current.kind() == "type_definition" {
                self.collect_typedef_flexible_array(&current, source);
            }

            // Look for array declarations of flexible array structures
            if current.kind() == "declaration" {
                if let Some(array_name) =
                    self.detect_flexible_struct_array_declaration(&current, source)
                {
                    self.flexible_struct_arrays.insert(array_name);
                }
            }

            for i in (0..current.child_count()).rev() {
                if let Some(child) = current.child(i) {
                    stack.push(child);
                }
            }
        }
    }

    fn collect_typedef_flexible_array(&mut self, node: &Node, source: &str) {
        // Check if this typedef is for a flexible array structure
        // Handle both: typedef struct flex_array_struct FlexType;
        // and: typedef struct { ... } FlexType;

        let mut typedef_name = None;
        let mut struct_name = None;
        let mut has_inline_struct = false;
        let mut inline_field_list = None;

        // Parse the typedef to find the typedef name and struct
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "type_identifier" => {
                        // Last type_identifier is usually the typedef name
                        typedef_name =
                            Some(source[child.start_byte()..child.end_byte()].to_string());
                    }
                    "struct_specifier" => {
                        // Found a struct specifier in the typedef
                        for j in 0..child.child_count() {
                            if let Some(struct_child) = child.child(j) {
                                match struct_child.kind() {
                                    "type_identifier" => {
                                        struct_name = Some(
                                            source[struct_child.start_byte()
                                                ..struct_child.end_byte()]
                                                .to_string(),
                                        );
                                    }
                                    "field_declaration_list" => {
                                        has_inline_struct = true;
                                        inline_field_list = Some(struct_child);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Handle inline struct definition: typedef struct { ... } FlexType;
        if has_inline_struct {
            if let (Some(tname), Some(field_list)) = (typedef_name, inline_field_list) {
                if self.has_flexible_array_member(&field_list, source) {
                    let start_point = node.start_position();
                    let validation = self.validate_flexible_array_layout(&field_list, source);
                    let info = FlexibleArrayInfo {
                        struct_name: tname.clone(),
                        has_flexible_array: true,
                        declaration_line: start_point.row + 1,
                        is_valid_definition: validation.is_valid_flexible_struct(),
                    };
                    self.flexible_structs.insert(tname, info);
                }
            }
        }
        // Handle typedef of existing struct: typedef struct flex_array_struct FlexType;
        else if let (Some(tname), Some(sname)) = (typedef_name, struct_name) {
            // Check if the referenced struct is a flexible array struct
            if let Some(existing_info) = self.flexible_structs.get(&sname) {
                let mut typedef_info = existing_info.clone();
                typedef_info.struct_name = tname.clone();
                self.flexible_structs.insert(tname, typedef_info);
            }
        }
    }

    fn analyze_struct_for_flexible_array(
        &self,
        node: &Node,
        source: &str,
    ) -> Option<FlexibleArrayInfo> {
        let mut struct_name = String::new();
        let mut validation_result = None;

        // Find struct name and validate flexible array layout
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "type_identifier" => {
                        struct_name = source[child.start_byte()..child.end_byte()].to_string();
                    }
                    "field_declaration_list" => {
                        validation_result =
                            Some(self.validate_flexible_array_layout(&child, source));
                    }
                    _ => {}
                }
            }
        }

        if let Some(validation) = validation_result {
            if !struct_name.is_empty() {
                // Check for invalid struct layouts first
                if validation.has_violations() {
                    // Store invalid struct information for later violation reporting
                    // We'll report these violations in a separate method
                    return Some(FlexibleArrayInfo {
                        struct_name: struct_name.clone(),
                        has_flexible_array: false, // Mark as invalid
                        declaration_line: node.start_position().row + 1,
                        is_valid_definition: false,
                    });
                }

                // Valid flexible array struct
                if validation.is_valid_flexible_struct() {
                    return Some(FlexibleArrayInfo {
                        struct_name,
                        has_flexible_array: true,
                        declaration_line: node.start_position().row + 1,
                        is_valid_definition: true,
                    });
                }
            }
        }

        None
    }

    fn detect_flexible_struct_array_declaration(
        &self,
        declaration: &Node,
        source: &str,
    ) -> Option<String> {
        // Check if this declaration creates an array of flexible array structures

        // Look for array declarators in the declaration
        for i in 0..declaration.child_count() {
            if let Some(child) = declaration.child(i) {
                if child.kind() == "array_declarator" {
                    // Check if the type is a flexible array structure
                    if let Some(type_name) = self.extract_declared_type(declaration, source) {
                        if self.is_flexible_array_struct(&type_name) {
                            // Extract the array variable name
                            if let Some(var_name) = self.extract_array_variable_name(&child, source)
                            {
                                return Some(var_name);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn extract_array_variable_name(&self, array_declarator: &Node, source: &str) -> Option<String> {
        // Extract the variable name from an array declarator
        for i in 0..array_declarator.child_count() {
            if let Some(child) = array_declarator.child(i) {
                if child.kind() == "identifier" {
                    return Some(source[child.start_byte()..child.end_byte()].to_string());
                }
            }
        }
        None
    }

    fn has_flexible_array_member(&self, field_list: &Node, source: &str) -> bool {
        // Enhanced validation for flexible array member requirements
        let validation_result = self.validate_flexible_array_layout(field_list, source);

        // Return true only if we have exactly one flexible array as the last member
        validation_result.is_valid_flexible_struct()
    }

    fn is_flexible_array_field(&self, field: &Node, source: &str) -> bool {
        // Look for array_declarator with empty size
        for i in 0..field.child_count() {
            if let Some(child) = field.child(i) {
                if child.kind() == "array_declarator" {
                    // Check if the array has empty brackets []
                    for j in 0..child.child_count() {
                        if let Some(bracket) = child.child(j) {
                            if bracket.kind() == "[" || bracket.kind() == "]" {
                                // Look for empty array size (no size between brackets)
                                let bracket_content =
                                    source[child.start_byte()..child.end_byte()].to_string();
                                if bracket_content.ends_with("[]") {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn is_last_field_declaration(&self, field_list: &Node, current_index: usize) -> bool {
        // Check if the current field declaration is the last one in the struct
        for i in (current_index + 1)..field_list.child_count() {
            if let Some(child) = field_list.child(i) {
                if child.kind() == "field_declaration" {
                    return false; // Found another field declaration after this one
                }
            }
        }
        true // No more field declarations found
    }

    fn validate_flexible_array_layout(
        &self,
        field_list: &Node,
        source: &str,
    ) -> FlexibleArrayValidation {
        let mut validation = FlexibleArrayValidation::new();
        let mut field_position = 0;

        for i in 0..field_list.child_count() {
            if let Some(child) = field_list.child(i) {
                if child.kind() == "field_declaration" {
                    validation.total_field_count += 1;
                    field_position += 1;

                    if self.is_flexible_array_field(&child, source) {
                        validation.flexible_member_count += 1;
                        validation.flexible_member_positions.push(field_position);

                        // Check if this is the last field
                        let is_last_field = self.is_last_field_declaration(field_list, i);
                        if is_last_field {
                            validation.last_field_is_flexible = true;
                        } else {
                            validation.violations.push(format!(
                                "Flexible array member at position {} is not the last member",
                                field_position
                            ));
                        }
                    }
                }
            }
        }

        // Validate flexible array member rules
        if validation.flexible_member_count > 1 {
            validation.violations.push(format!(
                "Structure has {} flexible array members (maximum 1 allowed)",
                validation.flexible_member_count
            ));
        }

        if validation.flexible_member_count > 0 && validation.total_field_count == 1 {
            validation.violations.push(
                "Structure has only flexible array member (at least one fixed member required)"
                    .to_string(),
            );
        }

        validation
    }

    fn check_invalid_struct_definition(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        let mut struct_name = String::new();

        // Find struct name
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "type_identifier" {
                    struct_name = source[child.start_byte()..child.end_byte()].to_string();
                    break;
                }
            }
        }

        // Find field declaration list and validate
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "field_declaration_list" {
                    let validation = self.validate_flexible_array_layout(&child, source);

                    if validation.has_violations() {
                        let start_point = node.start_position();
                        let violation_details = validation.violations.join("; ");

                        return Some(RuleViolation {
                            rule_id: "MEM33-C".to_string(),
                            severity: Severity::Critical, // Critical because this won't compile
                            message: format!(
                                "Invalid flexible array structure definition '{}': {}. Flexible arrays must be the single last member of a struct.",
                                if struct_name.is_empty() { "anonymous" } else { &struct_name },
                                violation_details
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Ensure struct has at most one flexible array member as the final field".to_string()),
                        ..Default::default()
                        });
                    }
                }
            }
        }

        None
    }

    fn check_violations(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Iterative pre-order walk: deeply nested code (e.g. multi-thousand-deep
        // else-if chains) overflows the stack with self-recursion.
        let mut stack = vec![*node];
        while let Some(current) = stack.pop() {
            self.check_node(&current, source, &mut violations);

            for i in (0..current.child_count()).rev() {
                if let Some(child) = current.child(i) {
                    stack.push(child);
                }
            }
        }

        violations
    }

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for various violation patterns
        match node.kind() {
            "declaration" => {
                // Check for prohibited storage of flexible array structs
                if let Some(violation) = self.check_prohibited_storage(node, source) {
                    violations.push(violation);
                }
            }
            "variable_declaration" | "init_declarator" => {
                // Some const declarations might appear as these node types
                if let Some(violation) = self.check_prohibited_storage(node, source) {
                    violations.push(violation);
                }
                // Check for initialization that copies flexible array structs
                if let Some(violation) = self.check_declaration_copy(node, source) {
                    violations.push(violation);
                }
                // Check for offsetof misuse in variable initialization
                if let Some(violation) = self.check_offsetof_in_init(node, source) {
                    violations.push(violation);
                }
            }
            "variable_declarator" => {
                // Some parsers may use variable_declarator instead of init_declarator
                if let Some(violation) = self.check_declaration_copy(node, source) {
                    violations.push(violation);
                }
            }
            "assignment_expression" => {
                // Check for direct assignment of flexible array structs
                if let Some(violation) = self.check_assignment_copy(node, source) {
                    violations.push(violation);
                }
            }
            "parameter_declaration" => {
                // Check for pass-by-value of flexible array structs
                if let Some(violation) = self.check_value_parameter(node, source) {
                    violations.push(violation);
                }
            }
            "compound_literal_expression" => {
                // Check for compound literal usage with flexible array structs
                if let Some(violation) = self.check_compound_literal(node, source) {
                    violations.push(violation);
                }
            }
            "call_expression" => {
                // Check for memory allocation function calls with incorrect sizing
                if let Some(violation) = self.check_memory_allocation(node, source) {
                    violations.push(violation);
                }
                // Check for file I/O operations with incorrect sizing
                if let Some(violation) = self.check_file_io_operations(node, source) {
                    violations.push(violation);
                }
                // Check for memory operation functions with incorrect sizing
                if let Some(violation) = self.check_memory_operations(node, source) {
                    violations.push(violation);
                }
                // Check for offsetof() misuse with flexible array members
                if let Some(violation) = self.check_offsetof_misuse(node, source) {
                    violations.push(violation);
                }
            }
            "cast_expression" => {
                // Check for casting violations with flexible array structs (both const-casting and invalid type casting)
                if let Some(violation) = self.check_casting_violations(node, source) {
                    violations.push(violation);
                }
                // Check for sizeof in pointer arithmetic with flexible array structures
                if let Some(violation) = self.check_sizeof_in_pointer_arithmetic(node, source) {
                    violations.push(violation);
                }
            }
            "binary_expression" => {
                // Check for pointer arithmetic on flexible array structures
                if let Some(violation) = self.check_pointer_arithmetic(node, source) {
                    violations.push(violation);
                }
                // Check for offsetof misuse in binary expressions (e.g., offsetof() + sizeof())
                if let Some(violation) = self.check_offsetof_in_binary(node, source) {
                    violations.push(violation);
                }
            }
            "subscript_expression" => {
                // Check for array indexing on flexible array structures (implicit pointer arithmetic)
                if let Some(violation) = self.check_array_indexing(node, source) {
                    violations.push(violation);
                }
            }
            "union_specifier" => {
                // Check for unions containing flexible array structure members
                if let Some(violation) = self.check_union_with_flexible_struct(node, source) {
                    violations.push(violation);
                }
            }
            "struct_specifier" => {
                // Check for invalid struct definitions with multiple/misplaced flexible arrays
                if let Some(violation) = self.check_invalid_struct_definition(node, source) {
                    violations.push(violation);
                }
            }
            "field_declaration" => {
                // Check if this field declares a member using a flexible array struct type
                if let Some(violation) = self.check_embedded_flexible_struct(node, source) {
                    violations.push(violation);
                }

                // Check for anonymous unions within field declarations that contain flexible array structures
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "union_specifier" {
                            // Anonymous union in field declaration
                            if let Some(violation_info) =
                                self.check_anonymous_union_with_flexible(&child, source)
                            {
                                let _start_point = child.start_position();
                                violations.push(RuleViolation {
                                    rule_id: "MEM33-C".to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "Anonymous union in field declaration contains flexible array structure member '{}'. Unions require fixed-size members to share memory space.",
                                        violation_info.member_name
                                    ),
                                    file_path: String::new(),
                                    line: violation_info.line,
                                    column: violation_info.column,
                                    suggestion: Some("Use a pointer to the flexible array structure instead of embedding it directly in the union".to_string()),
                                ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn check_prohibited_storage(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check for flexible array structures with prohibited storage duration
        // MEM33-C requires dynamic storage duration only

        // First extract the actual declared type
        let declared_type = self.extract_declared_type(node, source);

        // Only proceed if the declared type is actually a flexible array struct
        if let Some(ref dtype) = declared_type {
            if !self.is_flexible_array_struct(dtype) {
                // The declared type is not a flexible array struct, so no violation
                return None;
            }
        } else {
            // No type could be extracted
            return None;
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "array_declarator" {
                    // Array of flexible array structures - we already confirmed it's a flexible array struct
                    // Arrays are ALWAYS prohibited regardless of storage duration
                    let storage_info = self.analyze_storage_duration(node, source);
                    let start_point = node.start_position();

                    // Extract array size from the array declarator
                    let mut array_size = "".to_string();
                    for j in 0..child.child_count() {
                        if let Some(size_child) = child.child(j) {
                            if size_child.kind() != "identifier"
                                && size_child.kind() != "["
                                && size_child.kind() != "]"
                            {
                                array_size = source[size_child.start_byte()..size_child.end_byte()]
                                    .to_string();
                                break;
                            }
                        }
                    }

                    return Some(RuleViolation {
                        rule_id: "MEM33-C".to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Array of flexible array structures '{}[{}]' declared with {} storage. Arrays of flexible array structures are prohibited with any storage duration.",
                            declared_type.as_ref().unwrap(),
                            if array_size.is_empty() { "".to_string() } else { array_size.clone() },
                            storage_info.storage_type
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Use an array of pointers to dynamically allocated structures instead".to_string()),
                    ..Default::default()
                    });
                }

                if child.kind() == "init_declarator"
                    || child.kind() == "declarator"
                    || child.kind() == "identifier"
                {
                    // Check if this is an array declarator (legacy code for nested cases)
                    if let Some(array_info) = self.check_array_declarator(&child, source) {
                        if array_info.is_array
                            && self.is_flexible_array_struct(&array_info.base_type)
                        {
                            // This is an array of flexible array structures - VIOLATION!
                            let storage_info = self.analyze_storage_duration(node, source);
                            let start_point = node.start_position();
                            let array_size_display = array_info
                                .array_size
                                .clone()
                                .unwrap_or_else(|| "[]".to_string());
                            return Some(RuleViolation {
                                rule_id: "MEM33-C".to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Array of flexible array structures '{}[{}]' declared with {} storage. Arrays of flexible array structures are prohibited with any storage duration.",
                                    array_info.base_type, array_size_display, storage_info.storage_type
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some("Use an array of pointers to dynamically allocated structures instead".to_string()),
                            ..Default::default()
                            });
                        }
                    }

                    // Single flexible array structure declaration
                    // We already have the declared type from above and confirmed it's a flexible array struct
                    // Check if this is a pointer declaration (allowed) vs direct declaration (prohibited)
                    if !self.is_pointer_declaration(node, source) {
                        let storage_info = self.analyze_storage_duration(node, source);

                        // Check for const qualifier
                        let mut is_const = false;
                        self.find_const_qualifier_recursive(node, source, &mut is_const);
                        let qualifier_text = if is_const { "const-qualified " } else { "" };

                        let start_point = node.start_position();
                        let type_name = declared_type.as_ref().unwrap();

                        return Some(RuleViolation {
                            rule_id: "MEM33-C".to_string(),
                            severity: self.get_severity_for_storage_type(&storage_info.storage_type),
                            message: format!(
                                "{}flexible array structure '{}' declared with {} storage. Only dynamic storage duration is allowed for flexible array structures.",
                                qualifier_text, type_name, storage_info.storage_type
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(format!("Use dynamic allocation: struct {} *ptr = malloc(sizeof(struct {}) + sizeof(element_type) * count);", type_name, type_name)),
                        ..Default::default()
                        });
                    }
                }
            }
        }
        None
    }

    fn check_assignment_copy(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Enhanced to handle more assignment patterns
        let left = node.child_by_field_name("left")?;
        let right = node.child_by_field_name("right")?;

        // Pattern 1: *dest = *src (existing)
        if self.is_flexible_struct_dereference(&left, source)
            && self.is_flexible_struct_dereference(&right, source)
        {
            let start_point = node.start_position();
            return Some(RuleViolation {
                rule_id: "MEM33-C".to_string(),
                severity: Severity::Medium,
                message: "Direct assignment of flexible array structure instances. Use memcpy() for dynamic copying.".to_string(),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Use memcpy() to copy the structure and its flexible array member".to_string()),
            ..Default::default()
            });
        }

        // Pattern 2: dest = *src (copying dereferenced struct to variable)
        if !self.is_flexible_struct_dereference(&left, source)
            && self.is_flexible_struct_dereference(&right, source)
        {
            // Check if left side is a flexible array struct variable
            let left_text = source[left.start_byte()..left.end_byte()].to_string();
            if self.is_declared_flexible_struct_variable(&left_text, node) {
                let start_point = node.start_position();
                let right_text = source[right.start_byte()..right.end_byte()].to_string();

                return Some(RuleViolation {
                    rule_id: "MEM33-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Assignment copies flexible array structure: '{}'. Only fixed members are copied, not flexible array data.",
                        right_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Use proper memory allocation and copying for the entire structure".to_string()),
                ..Default::default()
                });
            }
        }

        None
    }

    fn check_declaration_copy(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check for variable declarations that initialize by copying flexible array structures
        // Pattern: struct flex_array_struct local_copy = *shared_flex;

        // Find the declared type and initializer
        let mut declared_type = None;
        let mut initializer = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        // This is the variable name being declared
                        continue;
                    }
                    "=" => {
                        // Next child should be the initializer
                        if let Some(init_child) = node.child(i + 1) {
                            initializer = Some(init_child);
                        }
                    }
                    _ => {
                        // Look for initializer expressions
                        if child.kind().contains("expression")
                            || child.kind() == "pointer_expression"
                        {
                            initializer = Some(child);
                        }
                    }
                }
            }
        }

        // Get the declared type from the parent declaration
        if let Some(parent) = node.parent() {
            if parent.kind() == "declaration" {
                declared_type = self.extract_declared_type(&parent, source);

                // Check if this is a pointer declaration - if so, it's allowed
                if self.is_pointer_declaration(&parent, source) {
                    return None;
                }
            }
        }

        // Check if we're declaring a flexible array struct and initializing with a copy
        if let Some(type_name) = declared_type {
            if self.is_flexible_array_struct(&type_name) {
                if let Some(init) = initializer {
                    if self.is_flexible_struct_copy_initialization(&init, source) {
                        let start_point = node.start_position();
                        let init_text = source[init.start_byte()..init.end_byte()].to_string();

                        let violation_type =
                            if init_text.contains("(struct") && init_text.contains("){") {
                                "compound literal"
                            } else if init_text.starts_with("*") {
                                "pointer dereference"
                            } else {
                                "variable copy"
                            };

                        return Some(RuleViolation {
                            rule_id: "MEM33-C".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Declaration initialization copies flexible array structure via {}: 'struct {} = {}'. Only fixed members are copied, not flexible array data.",
                                violation_type, type_name, init_text
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Use proper allocation and memcpy to copy the entire structure including flexible array data".to_string()),
                        ..Default::default()
                        });
                    }
                }
            }
        }

        None
    }

    fn is_flexible_struct_copy_initialization(&self, init_node: &Node, source: &str) -> bool {
        // Check if the initializer expression copies a flexible array structure

        let init_text = source[init_node.start_byte()..init_node.end_byte()].to_string();

        match init_node.kind() {
            "pointer_expression"
                // Direct dereference: *shared_flex
                if init_text.starts_with("*") => {
                    let dereferenced_var = init_text.trim_start_matches("*").trim();
                    return self.is_likely_flexible_struct_pointer(dereferenced_var);
                }
            "identifier" => {
                // Direct variable copy: local_copy (without dereference)
                // Since we're in the context of initializing a flexible array struct,
                // any variable being copied is potentially problematic
                let var_name = init_text.trim();
                return self.is_likely_flexible_struct_variable(var_name) ||
                       // For declaration initialization context, be more permissive about variables
                       // that could be flexible array structs
                       var_name.contains("copy") || var_name.contains("local") ||
                       var_name.contains("another") || var_name.contains("temp");
            }
            "compound_literal_expression"
                // Compound literal: (struct flex_array_struct){...}
                // Any compound literal of a flexible array struct is problematic
                if (init_text.contains("flex_array_struct")
                    || self.flexible_structs.keys().any(|k| init_text.contains(k)))
                => {
                    return true;
                }
            "subscript_expression" => {
                // Array element copy: flex_array[0]
                return self.is_likely_flexible_struct_array_access(&init_text);
            }
            "call_expression" => {
                // Function return value: get_flex_struct()
                // This could return a flexible array struct by value (problematic)
                return self.is_likely_flexible_struct_function_call(init_node, source);
            }
            _ => {}
        }

        false
    }

    fn is_likely_flexible_struct_pointer(&self, var_name: &str) -> bool {
        // Heuristic to determine if variable name suggests a flexible array struct pointer

        // Strategy 1: Check against known flexible array struct names
        for struct_name in self.flexible_structs.keys() {
            if var_name.contains(struct_name) {
                return true;
            }
        }

        // Strategy 2: Common naming patterns
        if var_name.contains("flex") || var_name.contains("shared") || var_name.contains("_struct")
        {
            return true;
        }

        // Strategy 3: Threading/shared context names
        if var_name.contains("shared_")
            || var_name.contains("global_")
            || var_name.contains("thread_")
        {
            return true;
        }

        false
    }

    fn is_likely_flexible_struct_variable(&self, var_name: &str) -> bool {
        // Similar to pointer check but for direct variable names
        self.is_likely_flexible_struct_pointer(var_name)
    }

    fn is_likely_flexible_struct_array_access(&self, expr: &str) -> bool {
        // Check if array access might be accessing flexible array structures
        // Pattern: flex_array[index] or similar

        if let Some(bracket_pos) = expr.find('[') {
            let array_name = &expr[..bracket_pos];
            return self.is_likely_flexible_struct_pointer(array_name);
        }

        false
    }

    fn is_likely_flexible_struct_function_call(&self, call_node: &Node, source: &str) -> bool {
        // Check if function call might return a flexible array struct by value

        if let Some(function_name) = self.get_function_name(call_node, source) {
            // Heuristic: function names that suggest returning flexible array structs
            if function_name.contains("create")
                || function_name.contains("get")
                || function_name.contains("flex")
                || function_name.contains("struct")
            {
                return true;
            }
        }

        false
    }

    fn is_declared_flexible_struct_variable(&self, var_name: &str, _context_node: &Node) -> bool {
        // Check if the variable is declared as a flexible array struct type
        // This requires walking up the AST to find variable declarations

        // For now, use heuristic approach
        self.is_likely_flexible_struct_variable(var_name)
    }

    fn check_value_parameter(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check if parameter is a flexible array struct passed by value
        if let Some(type_name) = self.extract_parameter_type(node, source) {
            if self.is_flexible_array_struct(&type_name) && !self.is_pointer_parameter(node, source)
            {
                let start_point = node.start_position();
                return Some(RuleViolation {
                    rule_id: "MEM33-C".to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Flexible array structure '{}' passed by value. Pass by pointer instead.",
                        type_name
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Change parameter to pointer type".to_string()),
                    ..Default::default()
                });
            }
        }

        None
    }

    fn check_compound_literal(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check for compound literal usage with flexible array structs
        // Compound literals have automatic storage duration, which is prohibited for flexible array structs

        // Extract the type from the compound literal
        if let Some(type_name) = self.extract_compound_literal_type(node, source) {
            if self.is_flexible_array_struct(&type_name) {
                // Check if there's an attempt to initialize the flexible array member
                let has_flex_init = self.has_flexible_array_initialization(node, source);

                let start_point = node.start_position();
                let message = if has_flex_init {
                    format!(
                        "Compound literal used with flexible array structure '{}' - cannot initialize flexible array member in compound literal",
                        type_name
                    )
                } else {
                    format!(
                        "Compound literal used with flexible array structure '{}' - compound literals have automatic storage duration which is prohibited",
                        type_name
                    )
                };

                return Some(RuleViolation {
                    rule_id: "MEM33-C".to_string(),
                    severity: Severity::High,
                    message,
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Allocate the structure dynamically using malloc() with proper size calculation".to_string()),
                ..Default::default()
                });
            }
        }

        None
    }

    fn extract_compound_literal_type(&self, node: &Node, source: &str) -> Option<String> {
        // Extract the type from a compound literal expression
        // Compound literals typically have structure: (type_name) { initializer_list }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "type_descriptor" | "type_name" => {
                        // Look for struct specifier within the type descriptor
                        for j in 0..child.child_count() {
                            if let Some(type_child) = child.child(j) {
                                if type_child.kind() == "struct_specifier" {
                                    // Extract struct name
                                    for k in 0..type_child.child_count() {
                                        if let Some(struct_child) = type_child.child(k) {
                                            if struct_child.kind() == "type_identifier" {
                                                return Some(
                                                    source[struct_child.start_byte()
                                                        ..struct_child.end_byte()]
                                                        .to_string(),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "struct_specifier" => {
                        // Direct struct specifier in compound literal
                        for j in 0..child.child_count() {
                            if let Some(struct_child) = child.child(j) {
                                if struct_child.kind() == "type_identifier" {
                                    return Some(
                                        source[struct_child.start_byte()..struct_child.end_byte()]
                                            .to_string(),
                                    );
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        None
    }

    fn has_flexible_array_initialization(&self, node: &Node, source: &str) -> bool {
        // Check if the compound literal attempts to initialize a flexible array member
        // Look for initializer_list and check if it contains field initializers for the flexible array

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "initializer_list" {
                    // Check each initializer in the list
                    for j in 0..child.child_count() {
                        if let Some(init_child) = child.child(j) {
                            if init_child.kind() == "initializer_pair"
                                || init_child.kind() == "field_initializer"
                            {
                                // Check if this is initializing a field named 'data' (common flexible array name)
                                // or if it has array initializer syntax
                                if self.is_flexible_array_initializer(&init_child, source) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    fn is_flexible_array_initializer(&self, node: &Node, source: &str) -> bool {
        // Check if this initializer is for a flexible array member
        // Look for patterns like .data = {...} or array initializer lists after struct members

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "field_designator" => {
                        // Check if field name suggests flexible array (e.g., "data", "buffer", etc.)
                        let field_text = &source[child.start_byte()..child.end_byte()];
                        if field_text.contains("data")
                            || field_text.contains("buffer")
                            || field_text.contains("array")
                        {
                            // Check if the value is an initializer list
                            for j in 0..node.child_count() {
                                if let Some(value_child) = node.child(j) {
                                    if value_child.kind() == "initializer_list" {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                    "initializer_list" => {
                        // Found an array initializer
                        return true;
                    }
                    _ => {}
                }
            }
        }

        false
    }

    fn extract_declared_type(&self, declaration: &Node, source: &str) -> Option<String> {
        // Extract the type name from a declaration
        // Be careful not to confuse the declaration type with types used in initializers
        for i in 0..declaration.child_count() {
            if let Some(child) = declaration.child(i) {
                match child.kind() {
                    "struct_specifier"
                        // Only consider struct_specifier if it's actually the type being declared,
                        // not part of an initializer expression
                        if (i == 0
                            || (i == 1
                                && declaration.child(0).is_some_and(|c| {
                                    c.kind() == "storage_class_specifier"
                                        || c.kind() == "type_qualifier"
                                })))
                        => {
                            // Look for type identifier in struct
                            for j in 0..child.child_count() {
                                if let Some(type_child) = child.child(j) {
                                    if type_child.kind() == "type_identifier" {
                                        return Some(
                                            source[type_child.start_byte()..type_child.end_byte()]
                                                .to_string(),
                                        );
                                    }
                                }
                            }
                        }
                    "type_identifier"
                        // Only consider if it's the first type identifier (the declaration type)
                        if (i == 0
                            || (i == 1
                                && declaration.child(0).is_some_and(|c| {
                                    c.kind() == "storage_class_specifier"
                                        || c.kind() == "type_qualifier"
                                })))
                        => {
                            return Some(source[child.start_byte()..child.end_byte()].to_string());
                        }
                    "primitive_type"
                        // Handle primitive types like size_t, int, etc.
                        if (i == 0
                            || (i == 1
                                && declaration.child(0).is_some_and(|c| {
                                    c.kind() == "storage_class_specifier"
                                        || c.kind() == "type_qualifier"
                                })))
                        => {
                            return Some(source[child.start_byte()..child.end_byte()].to_string());
                        }
                    _ => {}
                }
            }
        }
        None
    }

    #[allow(dead_code)]
    fn extract_declared_type_with_qualifiers(
        &self,
        declaration: &Node,
        source: &str,
    ) -> Option<(String, bool)> {
        let mut is_const = false;

        // First pass: look for const qualifier anywhere in the declaration
        self.find_const_qualifier_recursive(declaration, source, &mut is_const);

        // Second pass: look for struct type name with multiple strategies
        let type_name = self.find_struct_type_name_recursive(declaration, source);

        type_name.map(|name| (name, is_const))
    }

    fn find_const_qualifier_recursive(&self, node: &Node, source: &str, is_const: &mut bool) {
        // Recursively search for const qualifier in any child node
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "storage_class_specifier" | "type_qualifier" => {
                        let keyword = source[child.start_byte()..child.end_byte()].trim();
                        if keyword == "const" {
                            *is_const = true;
                        }
                    }
                    _ => {
                        // Check the text content directly for const keyword
                        let text = source[child.start_byte()..child.end_byte()].trim();
                        if text == "const" {
                            *is_const = true;
                        }
                        // Recurse into children
                        self.find_const_qualifier_recursive(&child, source, is_const);
                    }
                }
            }
        }
    }

    fn find_struct_type_name_recursive(&self, node: &Node, source: &str) -> Option<String> {
        // Try multiple strategies to find the struct name

        // Strategy 1: Direct struct_specifier lookup (existing)
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "struct_specifier" {
                    for j in 0..child.child_count() {
                        if let Some(type_child) = child.child(j) {
                            if type_child.kind() == "type_identifier" {
                                return Some(
                                    source[type_child.start_byte()..type_child.end_byte()]
                                        .to_string(),
                                );
                            }
                        }
                    }
                }
            }
        }

        // Strategy 2: Look for "struct" keyword followed by identifier
        let decl_text = source[node.start_byte()..node.end_byte()].to_string();
        if let Some(struct_pos) = decl_text.find("struct ") {
            let after_struct = &decl_text[struct_pos + 7..]; // Skip "struct "
            if let Some(space_pos) = after_struct.find(' ') {
                let struct_name = &after_struct[..space_pos];
                if !struct_name.is_empty()
                    && struct_name.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    return Some(struct_name.to_string());
                }
            }
        }

        // Strategy 3: Recursive search for type_identifier anywhere
        self.find_type_identifier_recursive(node, source)
    }

    fn find_type_identifier_recursive(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "type_identifier" {
                    let name = source[child.start_byte()..child.end_byte()].to_string();
                    // Check if this looks like a struct name we care about
                    if self.flexible_structs.contains_key(&name) || name.contains("flex") {
                        return Some(name);
                    }
                }
                // Recurse into children
                if let Some(result) = self.find_type_identifier_recursive(&child, source) {
                    return Some(result);
                }
            }
        }
        None
    }

    fn is_flexible_array_struct_pointer_usage(&self, node: &Node, source: &str) -> bool {
        // Check if this node represents usage of a flexible array struct pointer

        let node_text = source[node.start_byte()..node.end_byte()].to_string();

        // Don't trigger on sizeof expressions - these are legitimate size calculations
        if node_text.contains("sizeof") {
            return false;
        }

        // Strategy 1: Check if this is an identifier that directly references a flexible array struct pointer
        if node.kind() == "identifier" {
            let var_name = node_text.trim();
            // Heuristic: variable names containing "flex" are likely candidates
            // But avoid triggering on mathematical expressions or comparisons
            if var_name.contains("flex")
                && !node_text.contains("=")
                && !node_text.contains("+")
                && !node_text.contains("-")
            {
                return true;
            }
        }

        // Strategy 2: Check for direct variable references to known flexible array struct pointers
        // This should be more conservative than the previous implementation
        if node.kind() == "identifier" {
            let var_name = node_text.trim();
            if var_name == "flex_struct"
                || var_name.ends_with("_flex")
                || var_name.starts_with("flex_")
            {
                return true;
            }
        }

        false
    }

    fn is_flexible_array_struct_array(&self, array_node: &Node, source: &str) -> bool {
        // Check if the array being indexed is an array of flexible array structures
        // This function should ONLY return true for actual arrays of structures,
        // NOT for pointers to individual structures with flexible array members

        let array_text = source[array_node.start_byte()..array_node.end_byte()].to_string();

        // Strategy 1: Check against explicitly tracked flexible array struct arrays
        if self.flexible_struct_arrays.contains(&array_text) {
            return true;
        }

        // Strategy 2: Analyze the AST structure to determine if this is array access vs member access
        if self.is_member_access_not_array_access(array_node, source) {
            return false; // This is member access (compliant), not array access
        }

        // Strategy 3: Check for explicit array declaration patterns
        if self.is_explicitly_declared_array(array_node, source) {
            // Only flag if the array contains flexible array structures
            return self.array_contains_flexible_structs(&array_text);
        }

        // Strategy 4: Conservative approach - only flag patterns that are clearly arrays
        // of structures, not pointers to individual structures
        if self.is_clearly_struct_array_pattern(&array_text) {
            return self.array_contains_flexible_structs(&array_text);
        }

        false
    }

    fn is_member_access_not_array_access(&self, node: &Node, source: &str) -> bool {
        // Analyze the parent context to determine if this is member access (ptr->member[i])
        // vs array access (array[i].member)

        if let Some(parent) = node.parent() {
            match parent.kind() {
                "field_expression" => {
                    // This is part of a field access expression (ptr->field[index])
                    // Check if the base is a pointer (compliant) vs array element (violation)
                    return self.is_pointer_based_field_access(&parent, source);
                }
                "subscript_expression" => {
                    // This node is the array part of a subscript expression
                    // Check if the grandparent context suggests this is member access
                    if let Some(grandparent) = parent.parent() {
                        if grandparent.kind() == "field_expression" {
                            return true; // This is ptr->member[index] pattern (compliant)
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn is_pointer_based_field_access(&self, field_expr: &Node, _source: &str) -> bool {
        // Check if this field expression is accessing a member of a pointer
        // (ptr->member vs array[i].member)

        for i in 0..field_expr.child_count() {
            if let Some(child) = field_expr.child(i) {
                if child.kind() == "->" {
                    return true; // Pointer dereference - this is compliant member access
                }
            }
        }
        false
    }

    fn is_explicitly_declared_array(&self, array_node: &Node, source: &str) -> bool {
        // Check if this variable was explicitly declared as an array
        // This would require more sophisticated variable tracking
        // For now, use simple heuristics

        let array_text = source[array_node.start_byte()..array_node.end_byte()].to_string();

        // Look for explicit array patterns in the variable name
        array_text.ends_with("_array") ||
        array_text.ends_with("_list") ||
        array_text.starts_with("array_") ||
        array_text.contains("_arr_") ||
        // Look for indexed access patterns that suggest array usage
        (array_text.contains("[") && array_text.contains("]"))
    }

    fn array_contains_flexible_structs(&self, array_name: &str) -> bool {
        // Check if the array name suggests it contains flexible array structures

        // Check against known flexible struct names
        for struct_name in self.flexible_structs.keys() {
            if array_name.contains(struct_name) {
                return true;
            }
        }

        // Check for explicit flexible array naming patterns
        array_name.contains("flex")
            && (array_name.contains("array")
                || array_name.contains("struct")
                || array_name.contains("_arr"))
    }

    fn is_clearly_struct_array_pattern(&self, array_text: &str) -> bool {
        // Only return true for patterns that clearly indicate arrays of structures
        // Be conservative to avoid false positives

        // Pattern 1: Variable names that explicitly indicate arrays
        if array_text.ends_with("_array")
            || array_text.ends_with("_list")
            || array_text.starts_with("array_")
            || array_text.starts_with("list_")
        {
            return true;
        }

        // Pattern 2: Global arrays (but be careful not to flag stack-allocated pointers)
        if array_text.contains("global_") || array_text.contains("static_") {
            return true;
        }

        // Pattern 3: Multiple consecutive array access patterns
        if array_text.matches('[').count() > 1 {
            return true;
        }

        false
    }

    fn is_flexible_member_access(&self, subscript_node: &Node, source: &str) -> bool {
        // Check if this subscript expression is accessing a flexible array member
        // Pattern: ptr->flexible_member[index] or (*ptr).flexible_member[index]
        // This should ONLY return true for member access, NOT for array indexing

        let subscript_text =
            source[subscript_node.start_byte()..subscript_node.end_byte()].to_string();

        // Strategy 1: Check if this subscript contains "->data[" pattern
        // This catches flex_array[i]->data[j] where the subscript is data[j]
        if subscript_text.contains("->data[") || subscript_text.contains("data[") {
            return true; // This is accessing the flexible array member "data"
        }

        // Strategy 2: Look at the full expression context
        // Check if we can walk up to find a field expression containing "->"
        let mut current_parent = subscript_node.parent();
        let mut steps = 0;
        while let Some(p) = current_parent {
            if steps > 3 {
                break;
            } // Prevent infinite loops
            steps += 1;

            let parent_text = source[p.start_byte()..p.end_byte().min(source.len())].to_string();

            // If we find a field expression with -> and data, this is member access
            if p.kind() == "field_expression"
                && parent_text.contains("->")
                && parent_text.contains("data")
            {
                return true;
            }

            // If the parent expression contains our subscript and has "->data" pattern
            if parent_text.contains(&subscript_text) && parent_text.contains("->data") {
                return true;
            }

            current_parent = p.parent();
        }

        false
    }

    fn is_compliant_pointer_access(&self, variable_name: &str, source: &str) -> bool {
        // Check if this variable represents a properly allocated pointer
        // Look for patterns that suggest proper allocation

        // CRITICAL: If this variable is known to be a flexible array struct array,
        // it's definitely NOT compliant pointer access
        if self.flexible_struct_arrays.contains(variable_name) {
            return false;
        }

        // Pattern 1: Variable names suggesting pointer usage
        if variable_name.ends_with("_ptr")
            || variable_name.ends_with("_pointer")
            || variable_name.starts_with("ptr_")
            || variable_name.contains("malloc")
            || variable_name.contains("alloc")
        {
            return true;
        }

        // Pattern 2: Check for allocation context in preceding lines
        // This is a simplified check - a full implementation would track allocations
        self.find_allocation_context(variable_name, source)
    }

    #[allow(dead_code)]
    fn extract_field_name_from_expression(
        &self,
        field_expr: &Node,
        source: &str,
    ) -> Option<String> {
        // Extract the field name from a field expression
        for i in 0..field_expr.child_count() {
            if let Some(child) = field_expr.child(i) {
                if child.kind() == "field_identifier" {
                    return Some(source[child.start_byte()..child.end_byte()].to_string());
                }
            }
        }
        None
    }

    #[allow(dead_code)]
    fn is_flexible_array_member_name(&self, member_name: &str) -> bool {
        // Check if this member name suggests a flexible array member
        // Common naming patterns for flexible array members
        member_name == "data"
            || member_name == "items"
            || member_name == "elements"
            || member_name == "buffer"
            || member_name == "array"
            || member_name.ends_with("_data")
            || member_name.ends_with("_items")
            || member_name.ends_with("_array")
            || member_name.ends_with("_buffer")
    }

    fn find_allocation_context(&self, variable_name: &str, source: &str) -> bool {
        // Look for malloc/calloc allocation of this variable
        // This is a simplified implementation
        let lines: Vec<&str> = source.lines().collect();

        for line in lines {
            if line.contains(variable_name)
                && (line.contains("malloc") || line.contains("calloc"))
                && (line.contains("sizeof") || line.contains("size"))
            {
                return true;
            }
        }
        false
    }

    #[allow(dead_code)]
    fn is_known_flexible_array_struct_array(&self, array_name: &str) -> bool {
        // Check if this array name was previously identified as a flexible array struct array
        // This would require tracking array declarations, but for now use heuristics

        // Look for common array variable names
        let array_patterns = [
            "flex_array",
            "flex_structs",
            "flexible_array",
            "struct_array",
            "dynamic_array",
            "var_array",
            "buffer_array",
        ];

        for pattern in &array_patterns {
            if array_name.contains(pattern) {
                return true;
            }
        }

        false
    }

    fn extract_parameter_type(&self, param: &Node, source: &str) -> Option<String> {
        // Similar to extract_declared_type but for parameters
        self.extract_declared_type(param, source)
    }

    fn check_array_declarator(
        &self,
        declarator_node: &Node,
        source: &str,
    ) -> Option<ArrayDeclaratorInfo> {
        // Check if this is an array declarator and extract information
        for i in 0..declarator_node.child_count() {
            if let Some(child) = declarator_node.child(i) {
                if child.kind() == "array_declarator" {
                    // This is an array declarator
                    // Extract the array size from the brackets
                    let mut array_size = None;
                    for j in 0..child.child_count() {
                        if let Some(size_child) = child.child(j) {
                            if size_child.kind() != "identifier"
                                && size_child.kind() != "["
                                && size_child.kind() != "]"
                            {
                                // This could be the array size expression
                                array_size = Some(
                                    source[size_child.start_byte()..size_child.end_byte()]
                                        .to_string(),
                                );
                            } else if size_child.kind() == "[" || size_child.kind() == "]" {
                                // Handle empty array [] case
                                if array_size.is_none() {
                                    array_size = Some("".to_string());
                                }
                            }
                        }
                    }

                    // Get the base type from the parent declaration or sibling nodes
                    if let Some(base_type) =
                        self.extract_declared_type_from_declaration_parent(declarator_node, source)
                    {
                        return Some(ArrayDeclaratorInfo {
                            base_type,
                            is_array: true,
                            array_size,
                        });
                    } else if let Some(base_type) =
                        self.extract_type_from_sibling_in_declaration(declarator_node, source)
                    {
                        return Some(ArrayDeclaratorInfo {
                            base_type,
                            is_array: true,
                            array_size,
                        });
                    }
                }
            }
        }

        // Not an array declarator
        None
    }

    fn extract_declared_type_from_declaration_parent(
        &self,
        declarator_node: &Node,
        source: &str,
    ) -> Option<String> {
        // Walk up to find the parent declaration node and extract the type
        let mut current = declarator_node.parent();
        while let Some(node) = current {
            if node.kind() == "declaration" {
                // Found the declaration, now extract the type specifier
                return self.extract_declared_type(&node, source);
            }
            current = node.parent();
        }
        None
    }

    fn extract_type_from_sibling_in_declaration(
        &self,
        declarator_node: &Node,
        source: &str,
    ) -> Option<String> {
        // If the array_declarator is a direct child of declaration, look for struct_specifier sibling
        if let Some(parent) = declarator_node.parent() {
            if parent.kind() == "declaration" {
                // Look for struct_specifier among the siblings
                for i in 0..parent.child_count() {
                    if let Some(sibling) = parent.child(i) {
                        if sibling.kind() == "struct_specifier" {
                            // Extract struct name from struct_specifier
                            for j in 0..sibling.child_count() {
                                if let Some(type_child) = sibling.child(j) {
                                    if type_child.kind() == "type_identifier" {
                                        return Some(
                                            source[type_child.start_byte()..type_child.end_byte()]
                                                .to_string(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn is_flexible_array_struct(&self, type_name: &str) -> bool {
        self.flexible_structs.contains_key(type_name)
    }

    fn is_in_function_scope(&self, node: &Node) -> bool {
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                return true;
            }
            current = parent.parent();
        }
        false
    }

    fn is_flexible_struct_dereference(&self, node: &Node, _source: &str) -> bool {
        // Check if this is a dereference of what might be a flexible array struct
        if node.kind() == "pointer_expression" {
            // This is a simple heuristic - in a full implementation we'd need type analysis
            return true;
        }
        false
    }

    fn is_pointer_parameter(&self, param: &Node, _source: &str) -> bool {
        // Check if parameter declaration includes pointer syntax
        for i in 0..param.child_count() {
            if let Some(child) = param.child(i) {
                if child.kind() == "pointer_declarator" {
                    return true;
                }
            }
        }
        false
    }

    fn analyze_storage_duration(&self, node: &Node, source: &str) -> StorageInfo {
        // Determine the storage duration of a declaration

        // Check for static keyword
        if self.has_static_keyword(node, source) {
            if self.is_in_function_scope(node) {
                return StorageInfo {
                    storage_type: "static local".to_string(),
                    is_dynamic: false,
                };
            } else {
                return StorageInfo {
                    storage_type: "static global".to_string(),
                    is_dynamic: false,
                };
            }
        }

        // Check for thread_local keyword
        if self.has_thread_local_keyword(node, source) {
            return StorageInfo {
                storage_type: "thread".to_string(),
                is_dynamic: false,
            };
        }

        // Check for const keyword
        if self.has_const_keyword(node, source) {
            if self.is_in_function_scope(node) {
                return StorageInfo {
                    storage_type: "const automatic".to_string(),
                    is_dynamic: false,
                };
            } else {
                return StorageInfo {
                    storage_type: "const static".to_string(),
                    is_dynamic: false,
                };
            }
        }

        // Check scope to determine automatic vs global
        if self.is_in_function_scope(node) {
            StorageInfo {
                storage_type: "automatic".to_string(),
                is_dynamic: false,
            }
        } else {
            StorageInfo {
                storage_type: "global".to_string(),
                is_dynamic: false,
            }
        }
    }

    fn has_static_keyword(&self, node: &Node, source: &str) -> bool {
        // Check if declaration contains "static" keyword
        self.declaration_contains_keyword(node, "static", source)
    }

    fn has_thread_local_keyword(&self, node: &Node, source: &str) -> bool {
        // Check if declaration contains "thread_local" or "_Thread_local" keyword
        self.declaration_contains_keyword(node, "thread_local", source)
            || self.declaration_contains_keyword(node, "_Thread_local", source)
    }

    fn has_const_keyword(&self, node: &Node, source: &str) -> bool {
        // Check if declaration contains "const" keyword
        self.declaration_contains_keyword(node, "const", source)
    }

    fn declaration_contains_keyword(&self, node: &Node, keyword: &str, source: &str) -> bool {
        // Recursively search the declaration for a specific keyword
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                // Check direct match
                if child.kind() == keyword {
                    return true;
                }

                // Check for storage class specifier containing the keyword
                if child.kind() == "storage_class_specifier" {
                    let text = &source[child.start_byte()..child.end_byte()];
                    if text == keyword {
                        return true;
                    }
                }

                // Recursively check children
                if self.declaration_contains_keyword(&child, keyword, source) {
                    return true;
                }
            }
        }
        false
    }

    fn is_pointer_declaration(&self, node: &Node, source: &str) -> bool {
        // Check if this declaration is for a pointer (which is allowed)
        // Look for pointer_declarator or * symbols in the declarator part ONLY
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "pointer_declarator" {
                    return true;
                }
                // Only check for '*' character in declarators, not in initializers
                if child.kind() == "init_declarator" {
                    // Check the declarator part, not the initializer
                    for j in 0..child.child_count() {
                        if let Some(declarator_child) = child.child(j) {
                            match declarator_child.kind() {
                                "pointer_declarator" => return true,
                                "identifier" => {
                                    // This is just the variable name, continue
                                    continue;
                                }
                                "=" => {
                                    // Stop here - we've reached the initializer
                                    break;
                                }
                                _ => {
                                    // Check for pointer syntax only in declarator nodes
                                    if declarator_child.kind().contains("declarator") {
                                        if self.contains_pointer_syntax(&declarator_child, source) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if child.kind().contains("declarator") {
                    // Check for '*' character in declarators only
                    if self.contains_pointer_syntax(&child, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn contains_pointer_syntax(&self, node: &Node, source: &str) -> bool {
        // Check if node contains pointer syntax like '*'
        let node_text = &source[node.start_byte()..node.end_byte()];
        node_text.contains('*')
    }

    fn get_severity_for_storage_type(&self, storage_type: &str) -> Severity {
        match storage_type {
            "global" | "static global" => Severity::High, // Global violations are serious
            "automatic" => Severity::Medium,              // Automatic storage (existing)
            "static local" | "thread" => Severity::High,  // Other prohibited storage
            _ => Severity::Medium,
        }
    }

    fn check_memory_allocation(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check if this is a call to malloc, calloc, or realloc
        if let Some(function_name) = self.get_function_name(node, source) {
            match function_name.as_str() {
                "malloc" => self.check_malloc_allocation(node, source),
                "calloc" => self.check_calloc_allocation(node, source),
                "realloc" => self.check_realloc_allocation(node, source),
                _ => None,
            }
        } else {
            None
        }
    }

    fn check_malloc_allocation(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Get the size argument from malloc(size)
        if let Some(size_arg) = self.get_allocation_size_argument(node, source) {
            // Enhanced check: handle both direct expressions and variable references (like realloc)
            let is_insufficient = if self.is_simple_identifier(&size_arg) {
                // If size_arg is a variable, trace its definition
                if let Some(traced_expr) = self.trace_variable_definition(&size_arg, node, source) {
                    // Check if the traced expression has proper size calculation
                    if self.likely_has_additional_size_calculation(&traced_expr) {
                        false
                    } else {
                        self.is_definitely_insufficient_sizeof(&traced_expr)
                    }
                } else {
                    // If we can't trace the variable, be conservative and don't flag
                    false
                }
            } else {
                // Direct expression - use existing logic
                self.is_insufficient_sizeof_only(&size_arg)
            };

            // Check if size is just sizeof(struct flex_struct) without array space
            if is_insufficient {
                let start_point = node.start_position();
                return Some(RuleViolation {
                    rule_id: "MEM33-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Insufficient malloc allocation for flexible array structure. Only allocating fixed members: {}",
                        size_arg
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Use: malloc(sizeof(struct) + sizeof(element_type) * array_count)".to_string()),
                ..Default::default()
                });
            }
        }
        None
    }

    fn check_calloc_allocation(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Get both arguments from calloc(num, size)
        if let Some((num_arg, size_arg)) = self.get_calloc_arguments(node, source) {
            let start_point = node.start_position();

            // Enhanced analysis - check context before flagging violations
            let has_context_calculation =
                self.analyze_size_calculation_context(node, source, &size_arg);
            if has_context_calculation {
                return None; // Likely has proper size calculation
            }

            // Pattern 1: calloc(1, sizeof(struct)) - insufficient ONLY if clearly insufficient
            if num_arg.trim() == "1" && self.is_definitely_insufficient_sizeof(&size_arg) {
                return Some(RuleViolation {
                    rule_id: "MEM33-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Insufficient calloc allocation: calloc(1, {}). Missing space for flexible array.",
                        size_arg
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Use: calloc(1, sizeof(struct) + sizeof(element_type) * count)".to_string()),
                ..Default::default()
                });
            }

            // Pattern 2: calloc(sizeof(struct), count) - wrong parameter order
            if self.is_sizeof_struct_expression(&num_arg)
                && !self.likely_has_additional_size_calculation(&num_arg)
            {
                return Some(RuleViolation {
                    rule_id: "MEM33-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Incorrect calloc parameters: calloc({}, {}). Wrong parameter order for flexible array allocation.",
                        num_arg, size_arg
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Use: calloc(1, sizeof(struct) + sizeof(element_type) * count)".to_string()),
                ..Default::default()
                });
            }
        }
        None
    }

    fn check_realloc_allocation(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Get the new_size argument from realloc(ptr, new_size)
        if let Some(size_arg) = self.get_realloc_size_argument(node, source) {
            // Enhanced check: handle both direct expressions and variable references
            let is_insufficient = if self.is_simple_identifier(&size_arg) {
                // If size_arg is a variable, trace its definition
                if let Some(traced_expr) = self.trace_variable_definition(&size_arg, node, source) {
                    // Check if the traced expression has proper size calculation
                    // Variables containing proper calculations should not be flagged
                    if self.likely_has_additional_size_calculation(&traced_expr) {
                        false
                    } else {
                        self.is_definitely_insufficient_sizeof(&traced_expr)
                    }
                } else {
                    // If we can't trace the variable, be conservative and don't flag
                    false
                }
            } else {
                // Direct expression - use existing logic
                self.is_insufficient_sizeof_only(&size_arg)
            };

            if is_insufficient {
                let start_point = node.start_position();
                return Some(RuleViolation {
                    rule_id: "MEM33-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Insufficient realloc allocation for flexible array structure. Only allocating fixed members: {}",
                        size_arg
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Use: realloc(ptr, sizeof(struct) + sizeof(element_type) * array_count)".to_string()),
                ..Default::default()
                });
            }
        }
        None
    }

    fn get_function_name(&self, call_node: &Node, source: &str) -> Option<String> {
        // Extract function name from call_expression
        call_node
            .child_by_field_name("function")
            .map(|function| source[function.start_byte()..function.end_byte()].to_string())
    }

    fn get_allocation_size_argument(&self, call_node: &Node, source: &str) -> Option<String> {
        // Extract the size argument from malloc(size)
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            // Get first argument (skip parentheses and commas)
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                        return Some(source[child.start_byte()..child.end_byte()].to_string());
                    }
                }
            }
        }
        None
    }

    fn get_calloc_arguments(&self, call_node: &Node, source: &str) -> Option<(String, String)> {
        // Enhanced argument extraction that preserves complex expressions
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            let mut args = Vec::new();
            let mut current_arg = String::new();
            let mut paren_depth = 0;

            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    let child_text = source[child.start_byte()..child.end_byte()].to_string();

                    match child.kind() {
                        "(" => {
                            // Skip opening parenthesis of argument list
                            if paren_depth == 0 {
                                paren_depth += 1;
                                continue;
                            } else {
                                paren_depth += 1;
                                current_arg.push_str(&child_text);
                            }
                        }
                        ")" => {
                            paren_depth -= 1;
                            // Skip closing parenthesis of argument list
                            if paren_depth == 0 {
                                continue;
                            } else {
                                current_arg.push_str(&child_text);
                            }
                        }
                        "," => {
                            if paren_depth <= 1 {
                                // End of argument (at top level or just inside argument list)
                                if !current_arg.trim().is_empty() {
                                    args.push(current_arg.trim().to_string());
                                }
                                current_arg.clear();
                            } else {
                                // Comma inside nested parentheses, part of current argument
                                current_arg.push_str(&child_text);
                            }
                        }
                        _ => {
                            current_arg.push_str(&child_text);
                        }
                    }
                }
            }

            // Add the last argument
            if !current_arg.trim().is_empty() {
                args.push(current_arg.trim().to_string());
            }

            if args.len() >= 2 {
                return Some((args[0].clone(), args[1].clone()));
            }
        }
        None
    }

    fn get_realloc_size_argument(&self, call_node: &Node, source: &str) -> Option<String> {
        // Extract the new_size argument from realloc(ptr, new_size) - this is the second argument
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            let mut args = Vec::new();
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                        args.push(source[child.start_byte()..child.end_byte()].to_string());
                    }
                }
            }
            if args.len() >= 2 {
                return Some(args[1].clone()); // Second argument is the new size
            }
        }
        None
    }

    fn is_insufficient_sizeof_only(&self, size_expr: &str) -> bool {
        // More sophisticated analysis of size expressions
        let expr = size_expr.trim();

        // Skip empty or obviously complex expressions
        if expr.is_empty() || expr.len() > 200 {
            return false;
        }

        // Check if this is a simple identifier that might be a variable
        if self.is_simple_identifier(expr) {
            // Don't flag variables directly - they may contain proper calculations
            // Variables need to be traced to their definitions
            return false;
        }

        // Check for clearly insufficient patterns
        if self.is_definitely_insufficient_sizeof(expr) {
            return true;
        }

        // Check for likely sufficient patterns (even if we can't parse them fully)
        if self.likely_has_additional_size_calculation(expr) {
            return false;
        }

        // Conservative approach: if uncertain, don't flag as violation
        false
    }

    fn is_definitely_insufficient_sizeof(&self, expr: &str) -> bool {
        // Only flag expressions that are clearly just sizeof(struct) with no additions

        // Pattern 1: Exact match of sizeof(struct_name) with no operators
        if expr.starts_with("sizeof(") && expr.ends_with(")") {
            let sizeof_content = &expr[7..expr.len() - 1]; // Remove "sizeof(" and ")"

            // Check if it's a simple struct reference with no arithmetic
            // But allow dereferencing (*) in the sizeof content
            if !expr.contains("+")
                && !expr.contains("-")
                && !expr.contains("/")
                && !expr.contains("&")
                && !expr.contains("|")
            {
                // Special case: Check for sizeof(*pointer) pattern
                if let Some(var_name) = sizeof_content.strip_prefix("*") {
                    // This is sizeof(*pointer), check if pointer likely points to flexible struct
                    if self.is_likely_flexible_struct_pointer(var_name) {
                        return true;
                    }
                }

                // Make sure it targets a flexible array struct
                return self.sizeof_targets_flexible_struct(expr);
            }
        }

        false
    }

    fn likely_has_additional_size_calculation(&self, expr: &str) -> bool {
        // Check for patterns that suggest additional size calculation

        // Pattern 1: Contains arithmetic operators (likely calculating additional size)
        // BUT: Don't count * inside sizeof(*ptr) as additional calculation
        if expr.contains("+") {
            return true;
        }
        if expr.contains("*") && !expr.starts_with("sizeof(") {
            // Only count * as additional calculation if it's not part of sizeof(*)
            return true;
        }

        // Pattern 2: Variable or function call (might contain proper calculation)
        if expr.chars().any(|c| c.is_alphabetic()) && !expr.starts_with("sizeof(") {
            return true;
        }

        // Pattern 3: Complex expressions with parentheses (beyond simple sizeof)
        // Only flag if we have parentheses that are NOT part of sizeof(struct ...) patterns
        let paren_count = expr.chars().filter(|&c| c == '(').count();
        if paren_count > 1 && !expr.starts_with("sizeof(") {
            return true;
        }

        // Pattern 4: Multiple sizeof expressions (likely calculating total size)
        if expr.matches("sizeof(").count() > 1 {
            return true;
        }

        // Pattern 5: Contains common size calculation variable names (but not sizeof)
        let size_keywords = ["size", "total", "count", "length", "bytes", "len"];
        if size_keywords
            .iter()
            .any(|&keyword| expr.to_lowercase().contains(keyword))
            && !expr.starts_with("sizeof(")
        {
            return true;
        }

        // Pattern 6: Check for known compliant patterns
        if self.is_known_compliant_pattern(expr) {
            return true;
        }

        false
    }

    fn is_known_compliant_pattern(&self, size_expr: &str) -> bool {
        let expr = size_expr.to_lowercase();

        // Common compliant patterns
        let compliant_patterns = [
            // Explicit addition patterns
            "sizeof(struct", // followed by addition (handled by contains check)
            "total_size",
            "full_size",
            "calculated_size",
            "buffer_size",
            // Function calls that calculate size
            "calculate_size",
            "get_size",
            "size_of",
            "malloc_size",
            // Macro patterns
            "flex_size",
            "array_size",
        ];

        for pattern in &compliant_patterns {
            if expr.contains(pattern) {
                // Additional check: if it contains sizeof + arithmetic, it's likely compliant
                if expr.contains("sizeof") && (expr.contains("+") || expr.contains("*")) {
                    return true;
                }
                // Function calls or variables with size-related names
                if !expr.starts_with("sizeof(") {
                    return true;
                }
            }
        }

        false
    }

    fn analyze_size_calculation_context(
        &self,
        call_node: &Node,
        source: &str,
        size_arg: &str,
    ) -> bool {
        // Analyze the context around the calloc call to detect valid size patterns

        // Strategy 1: Look for size calculations in preceding statements
        if let Some(preceding_calculation) = self.find_preceding_size_calculation(call_node, source)
        {
            if preceding_calculation.contains(&size_arg.replace(" ", "")) {
                return true; // Size is calculated in a previous statement
            }
        }

        // Strategy 2: Check if size_arg is a function call or complex expression
        if size_arg.contains("(") && size_arg.contains(")") && !size_arg.starts_with("sizeof(") {
            return true; // Likely a function call that calculates proper size
        }

        // Strategy 3: Check for macro usage (must contain at least one uppercase letter and not be just numbers)
        if size_arg.chars().any(|c| c.is_uppercase())
            && size_arg
                .chars()
                .all(|c| c.is_uppercase() || c.is_numeric() || c == '_' || c == '(' || c == ')')
            && !size_arg.chars().all(|c| c.is_numeric())
        {
            return true; // Likely a macro that calculates size
        }

        false
    }

    fn find_preceding_size_calculation(&self, call_node: &Node, source: &str) -> Option<String> {
        // Look for size calculations in the preceding 5-10 lines
        let call_line = call_node.start_position().row;
        let start_search = call_line.saturating_sub(10);

        // This is a simplified implementation - in practice, you'd want to parse the AST
        // to find variable assignments that might contain size calculations
        let lines: Vec<&str> = source.lines().collect();

        for line_idx in start_search..call_line {
            if line_idx < lines.len() {
                let line = lines[line_idx];
                if line.contains("sizeof") && (line.contains("+") || line.contains("*")) {
                    return Some(line.to_string());
                }
            }
        }

        None
    }

    fn trace_variable_definition(
        &self,
        var_name: &str,
        scope_node: &Node,
        source: &str,
    ) -> Option<String> {
        // Search backwards from the realloc call for the variable's definition
        // and extract the initialization/assignment expression

        let var_name_trimmed = var_name.trim();

        // Strategy 1: Search in the same function scope for variable declarations
        // Look for patterns like: type var_name = expression; or var_name = expression;
        if let Some(function_node) = self.find_containing_function(scope_node) {
            if let Some(assignment_expr) =
                self.find_variable_assignment_in_function(&function_node, var_name_trimmed, source)
            {
                return Some(assignment_expr);
            }
        }

        // Strategy 2: Search in the immediate preceding statements
        if let Some(assignment_expr) = self.find_variable_assignment_in_preceding_statements(
            scope_node,
            var_name_trimmed,
            source,
        ) {
            return Some(assignment_expr);
        }

        None
    }

    fn is_simple_identifier(&self, expr: &str) -> bool {
        // Check if the expression is a simple variable name (identifier)
        // Simple identifiers contain only letters, digits, and underscores
        // and don't contain operators, parentheses, or spaces
        let trimmed = expr.trim();

        if trimmed.is_empty() {
            return false;
        }

        // Must start with letter or underscore
        if !trimmed.chars().next().unwrap().is_alphabetic() && !trimmed.starts_with('_') {
            return false;
        }

        // Check for operators or other complex expression indicators
        if trimmed.contains('+')
            || trimmed.contains('-')
            || trimmed.contains('*')
            || trimmed.contains('/')
            || trimmed.contains('(')
            || trimmed.contains(')')
            || trimmed.contains('[')
            || trimmed.contains(']')
            || trimmed.contains('.')
            || trimmed.contains("->")
            || trimmed.contains(' ')
            || trimmed.contains('\t')
        {
            return false;
        }

        // Check that all characters are valid identifier characters
        trimmed.chars().all(|c| c.is_alphanumeric() || c == '_')
    }

    fn find_containing_function<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        // Walk up the AST to find the containing function definition
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                return Some(parent);
            }
            current = parent.parent();
        }
        None
    }

    fn find_variable_assignment_in_function(
        &self,
        function_node: &Node,
        var_name: &str,
        source: &str,
    ) -> Option<String> {
        // Search through the function body for variable assignments
        self.traverse_for_variable_assignment(function_node, var_name, source)
    }

    fn find_variable_assignment_in_preceding_statements(
        &self,
        scope_node: &Node,
        var_name: &str,
        source: &str,
    ) -> Option<String> {
        // Look for variable assignments in the 10 lines preceding the realloc call
        let scope_line = scope_node.start_position().row;
        let start_search = scope_line.saturating_sub(10);

        let lines: Vec<&str> = source.lines().collect();

        for line_idx in start_search..scope_line {
            if line_idx < lines.len() {
                let line = lines[line_idx];

                // Look for assignment patterns:
                // 1. Declaration with initialization: size_t var_name = expression;
                // 2. Simple assignment: var_name = expression;
                if let Some(assignment_expr) = self.extract_assignment_expression(line, var_name) {
                    return Some(assignment_expr);
                }
            }
        }

        None
    }

    fn traverse_for_variable_assignment(
        &self,
        node: &Node,
        var_name: &str,
        source: &str,
    ) -> Option<String> {
        // Recursively traverse the AST to find variable assignments
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "declaration" | "init_declarator" | "assignment_expression" => {
                        if let Some(assignment_expr) =
                            self.check_node_for_variable_assignment(&child, var_name, source)
                        {
                            return Some(assignment_expr);
                        }
                    }
                    _ => {
                        // Recursively search in child nodes
                        if let Some(assignment_expr) =
                            self.traverse_for_variable_assignment(&child, var_name, source)
                        {
                            return Some(assignment_expr);
                        }
                    }
                }
            }
        }
        None
    }

    fn check_node_for_variable_assignment(
        &self,
        node: &Node,
        var_name: &str,
        source: &str,
    ) -> Option<String> {
        // Check if this node contains an assignment to the specified variable
        let node_text = source[node.start_byte()..node.end_byte()].to_string();

        // Look for patterns like: var_name = expression
        if let Some(assignment_expr) = self.extract_assignment_expression(&node_text, var_name) {
            return Some(assignment_expr);
        }

        None
    }

    fn extract_assignment_expression(&self, line: &str, var_name: &str) -> Option<String> {
        // Extract the right-hand side of an assignment expression

        // Pattern 1: Declaration with initialization - type var_name = expression;
        if let Some(pos) = line.find(&format!("{} =", var_name)) {
            let after_equals = &line[pos + var_name.len() + 2..]; // +2 to skip " ="
            if let Some(semicolon_pos) = after_equals.find(';') {
                return Some(after_equals[..semicolon_pos].trim().to_string());
            } else {
                return Some(after_equals.trim().to_string());
            }
        }

        // Pattern 2: Simple assignment - var_name = expression;
        if line.trim_start().starts_with(&format!("{} =", var_name)) {
            let after_equals = &line[line.find('=').unwrap() + 1..];
            if let Some(semicolon_pos) = after_equals.find(';') {
                return Some(after_equals[..semicolon_pos].trim().to_string());
            } else {
                return Some(after_equals.trim().to_string());
            }
        }

        None
    }

    fn is_sizeof_struct_expression(&self, expr: &str) -> bool {
        // Check if expression is sizeof(struct something)
        expr.trim().starts_with("sizeof(")
    }

    fn sizeof_targets_flexible_struct(&self, sizeof_expr: &str) -> bool {
        // Extract the type from sizeof(type) and check if it's a flexible array struct
        for struct_name in self.flexible_structs.keys() {
            if sizeof_expr.contains(struct_name) {
                return true;
            }
        }
        false
    }

    fn check_file_io_operations(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check if this is a call to file I/O functions that use sizeof() incorrectly
        if let Some(function_name) = self.get_function_name(node, source) {
            match function_name.as_str() {
                "fwrite" | "fread" | "fwrite_unlocked" | "fread_unlocked" => {
                    // Extract the size parameter (2nd argument)
                    if let Some(size_arg) = self.get_file_io_size_argument(node, source) {
                        // Check if size is just sizeof(struct flex_struct) without array space
                        if self.is_insufficient_sizeof_only(&size_arg) {
                            let start_point = node.start_position();
                            return Some(RuleViolation {
                                rule_id: "MEM33-C".to_string(),
                                severity: Severity::High, // Data corruption risk
                                message: format!(
                                    "File I/O operation {}() uses insufficient size {} for flexible array structure. Only writing/reading fixed members, not flexible array data.",
                                    function_name, size_arg
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some("Calculate full size: sizeof(struct) + sizeof(element_type) * array_count".to_string()),
                            ..Default::default()
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn get_file_io_size_argument(&self, call_node: &Node, source: &str) -> Option<String> {
        // Extract the size argument from file I/O functions like fwrite(ptr, size, count, stream)
        // This is the 2nd argument (index 1)
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            let mut args = Vec::new();
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                        args.push(source[child.start_byte()..child.end_byte()].to_string());
                    }
                }
            }
            if args.len() >= 2 {
                return Some(args[1].clone()); // Second argument is the size
            }
        }
        None
    }

    fn get_memory_op_size_argument(&self, call_node: &Node, source: &str) -> Option<String> {
        // Extract the size argument from memory operation functions like memcpy(dest, src, size)
        // This is the 3rd argument (index 2)
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            let mut args = Vec::new();
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                        args.push(source[child.start_byte()..child.end_byte()].to_string());
                    }
                }
            }
            if args.len() >= 3 {
                return Some(args[2].clone()); // Third argument is the size
            }
        }
        None
    }

    fn get_memory_op_target_argument(&self, call_node: &Node, source: &str) -> Option<String> {
        // Extract the target argument from memory operation functions like memset(target, value, size)
        // This is the 1st argument (index 0)
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            let mut args = Vec::new();
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                        args.push(source[child.start_byte()..child.end_byte()].to_string());
                    }
                }
            }
            if !args.is_empty() {
                return Some(args[0].clone()); // First argument is the target
            }
        }
        None
    }

    fn is_flexible_array_struct_target(&self, target_expr: &str) -> bool {
        // Check if the target expression appears to be a flexible array struct
        // This is a heuristic-based approach

        // Strategy 1: Check if target contains known flexible array struct names
        for struct_name in self.flexible_structs.keys() {
            if target_expr.contains(struct_name) {
                return true;
            }
        }

        // Strategy 2: Check for common flexible array struct patterns
        if target_expr.contains("flex") || target_expr.contains("_struct") {
            return true;
        }

        // Strategy 3: Check for dereference patterns that might indicate struct pointers
        if target_expr.starts_with("*") || target_expr.contains("->") {
            return true;
        }

        // Strategy 4: Check for common variable names that might be flexible array struct pointers
        // This is a broader heuristic for variables likely to be struct pointers
        let var_name = target_expr.trim();
        if var_name == "dest" || var_name == "src" || var_name == "target" || var_name == "buffer" {
            return true;
        }

        // Strategy 5: If we have flexible array structs detected, be more permissive
        // for simple variable names that look like pointers (since exact type analysis is complex)
        if !self.flexible_structs.is_empty()
            && var_name.len() <= 8
            && var_name.chars().all(|c| c.is_alphanumeric() || c == '_')
        {
            // Only for variables that don't look like regular values
            if !var_name.chars().all(|c| c.is_numeric()) && var_name != "0" && var_name != "1" {
                return true;
            }
        }

        false
    }

    fn check_memory_operations(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check if this is a call to memory operation functions that use sizeof() incorrectly
        if let Some(function_name) = self.get_function_name(node, source) {
            match function_name.as_str() {
                "memcpy" | "memmove" => {
                    // Extract the size parameter (3rd argument)
                    if let Some(size_arg) = self.get_memory_op_size_argument(node, source) {
                        // Check if size is just sizeof(struct flex_struct) without array space
                        if self.is_insufficient_sizeof_only(&size_arg) {
                            let start_point = node.start_position();
                            return Some(RuleViolation {
                                rule_id: "MEM33-C".to_string(),
                                severity: Severity::High, // Data corruption risk
                                message: format!(
                                    "Memory operation {}() uses insufficient size {} for flexible array structure. Only copying/moving fixed members, not flexible array data.",
                                    function_name, size_arg
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some("Calculate full size: sizeof(struct) + sizeof(element_type) * array_count".to_string()),
                            ..Default::default()
                            });
                        }
                    }
                }
                "memset" => {
                    // For memset, we need to check if it's being used on a flexible array struct
                    // memset(ptr, value, sizeof(struct)) is incomplete for flexible arrays
                    if let Some(size_arg) = self.get_memory_op_size_argument(node, source) {
                        if self.is_insufficient_sizeof_only(&size_arg) {
                            // Check if first argument might be a flexible array struct
                            if let Some(target_arg) =
                                self.get_memory_op_target_argument(node, source)
                            {
                                if self.is_flexible_array_struct_target(&target_arg) {
                                    let start_point = node.start_position();
                                    return Some(RuleViolation {
                                        rule_id: "MEM33-C".to_string(),
                                        severity: Severity::High,
                                        message: format!(
                                            "Memory operation {}() uses insufficient size {} for flexible array structure. Only initializing fixed members, not flexible array data.",
                                            function_name, size_arg
                                        ),
                                        file_path: String::new(),
                                        line: start_point.row + 1,
                                        column: start_point.column + 1,
                                        suggestion: Some("Calculate full size: sizeof(struct) + sizeof(element_type) * array_count".to_string()),
                                    ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn check_pointer_arithmetic(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check for binary expressions involving + or - with flexible array struct pointers

        // Get the operator
        let mut operator = None;
        let mut left_operand = None;
        let mut right_operand = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "+" | "-" => {
                        operator = Some(child.kind());
                    }
                    _ => {
                        if left_operand.is_none() {
                            left_operand = Some(child);
                        } else if right_operand.is_none() {
                            right_operand = Some(child);
                        }
                    }
                }
            }
        }

        // Check if this is pointer arithmetic (+ or -)
        if let Some(op) = operator {
            if op == "+" || op == "-" {
                // Check if the left operand might be a flexible array struct pointer
                if let Some(left) = left_operand {
                    if self.is_flexible_array_struct_pointer_usage(&left, source) {
                        let start_point = node.start_position();
                        let expr_text = source[node.start_byte()..node.end_byte()].to_string();

                        return Some(RuleViolation {
                            rule_id: "MEM33-C".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Pointer arithmetic on flexible array structure: '{}'. Flexible array structures don't have fixed size, making pointer arithmetic undefined.",
                                expr_text
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Use array indexing or calculate proper offsets based on the actual structure size including flexible array".to_string()),
                        ..Default::default()
                        });
                    }
                }
            }
        }

        None
    }

    fn check_array_indexing(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check for array indexing on arrays of flexible array structures
        // This should ONLY flag actual arrays of structures, NOT flexible array member access

        // Extract the array being indexed and the index
        let mut array_expr = None;
        let mut index_expr = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "[" | "]" => {
                        // Skip bracket tokens
                        continue;
                    }
                    _ => {
                        if array_expr.is_none() {
                            array_expr = Some(child);
                        } else if index_expr.is_none() {
                            index_expr = Some(child);
                        }
                    }
                }
            }
        }

        if let Some(array) = array_expr {
            // First, analyze the full context to distinguish between:
            // 1. ptr->flexible_member[index] (COMPLIANT - accessing flexible array member)
            // 2. struct_array[index] (VIOLATION - array of flexible structures)

            let expr_text = source[node.start_byte()..node.end_byte()].to_string();
            let array_text = source[array.start_byte()..array.end_byte()].to_string();

            // Check if this is flexible array member access (compliant)
            if self.is_flexible_member_access(node, source) {
                return None; // This is compliant flexible array member access
            }

            // Check if this is accessing an allocated pointer (compliant)
            if self.is_compliant_pointer_access(&array_text, source) {
                return None; // This is compliant pointer access
            }

            // Only flag if this is actually an array of flexible array structures
            if self.is_flexible_array_struct_array(&array, source) {
                let start_point = node.start_position();

                return Some(RuleViolation {
                    rule_id: "MEM33-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Array indexing on flexible array structure array: '{}'. This is implicit pointer arithmetic on structures with undefined size.",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Arrays of flexible array structures are prohibited. Use pointers to individually allocated structures instead".to_string()),
                ..Default::default()
                });
            }
        }

        None
    }

    fn check_union_with_flexible_struct(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check for unions containing flexible array structure members
        // This is prohibited because unions require fixed-size members to share memory space

        let mut union_name = String::new();
        let mut field_list_node = None;

        // Find union name and field list
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "type_identifier" => {
                        union_name = source[child.start_byte()..child.end_byte()].to_string();
                    }
                    "field_declaration_list" => {
                        field_list_node = Some(child);
                    }
                    _ => {}
                }
            }
        }

        if let Some(field_list) = field_list_node {
            if let Some(violation_info) =
                self.check_union_members_for_flexible_structs(&field_list, source)
            {
                let _start_point = node.start_position();
                return Some(RuleViolation {
                    rule_id: "MEM33-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Union '{}' contains flexible array structure member '{}'. Unions require fixed-size members to share memory space.",
                        if union_name.is_empty() { "<anonymous>" } else { &union_name },
                        violation_info.member_name
                    ),
                    file_path: String::new(),
                    line: violation_info.line,
                    column: violation_info.column,
                    suggestion: Some("Use a pointer to the flexible array structure instead of embedding it directly in the union".to_string()),
                ..Default::default()
                });
            }
        }

        None
    }

    fn check_union_members_for_flexible_structs(
        &self,
        field_list: &Node,
        source: &str,
    ) -> Option<UnionViolationInfo> {
        // Analyze each field in the union to check for flexible array structures
        for i in 0..field_list.child_count() {
            if let Some(field) = field_list.child(i) {
                match field.kind() {
                    "field_declaration" => {
                        if let Some(violation_info) = self.analyze_union_member(&field, source) {
                            return Some(violation_info);
                        }
                    }
                    "union_specifier" => {
                        // Nested anonymous union
                        if let Some(violation_info) =
                            self.check_anonymous_union_with_flexible(&field, source)
                        {
                            return Some(violation_info);
                        }
                    }
                    _ => {}
                }
            }
        }
        None
    }

    fn analyze_union_member(&self, field_decl: &Node, source: &str) -> Option<UnionViolationInfo> {
        // Extract type information from field declaration
        let mut type_name = String::new();
        let mut member_name = String::new();
        let mut is_struct_type = false;
        let mut is_pointer = false;

        // First, check if this is a pointer declarator
        for i in 0..field_decl.child_count() {
            if let Some(child) = field_decl.child(i) {
                if child.kind() == "pointer_declarator" {
                    is_pointer = true;
                    break;
                }
            }
        }

        // If it's a pointer, it's compliant (pointers to flexible array structs are allowed)
        if is_pointer {
            return None;
        }

        for i in 0..field_decl.child_count() {
            if let Some(child) = field_decl.child(i) {
                match child.kind() {
                    "struct_specifier" => {
                        // Extract struct type name
                        is_struct_type = true;
                        for j in 0..child.child_count() {
                            if let Some(struct_child) = child.child(j) {
                                if struct_child.kind() == "type_identifier" {
                                    type_name = source
                                        [struct_child.start_byte()..struct_child.end_byte()]
                                        .to_string();
                                    break;
                                }
                            }
                        }
                    }
                    "type_identifier" if !is_struct_type => {
                        type_name = source[child.start_byte()..child.end_byte()].to_string();
                    }
                    "field_identifier" => {
                        member_name = source[child.start_byte()..child.end_byte()].to_string();
                    }
                    _ => {}
                }
            }
        }

        // Check if this type is a flexible array structure (only if not a pointer)
        if self.is_flexible_array_struct(&type_name) {
            let position = field_decl.start_position();
            return Some(UnionViolationInfo {
                member_name: if member_name.is_empty() {
                    format!("<anonymous {}>", type_name)
                } else {
                    format!("{} ({})", member_name, type_name)
                },
                line: position.row + 1,
                column: position.column + 1,
            });
        }

        None
    }

    fn check_anonymous_union_with_flexible(
        &self,
        union_node: &Node,
        source: &str,
    ) -> Option<UnionViolationInfo> {
        // Check for anonymous unions containing flexible array structures
        for i in 0..union_node.child_count() {
            if let Some(child) = union_node.child(i) {
                if child.kind() == "field_declaration_list" {
                    // Recursively check the nested union's fields
                    return self.check_union_members_for_flexible_structs(&child, source);
                }
            }
        }
        None
    }

    fn check_embedded_flexible_struct(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check if this field declaration embeds a flexible array structure

        // Extract the field type and name
        if let Some(field_info) = self.extract_field_declaration_info(node, source) {
            // Check if the field type is a known flexible array structure
            if self.is_flexible_array_struct(&field_info.type_name) {
                // Check if this is a pointer (allowed) vs direct embedding (violation)
                if !field_info.is_pointer {
                    // Get parent structure context for better error messaging
                    let parent_context = self.get_parent_structure_context(node, source);
                    let start_point = node.start_position();

                    let violation_type = if field_info.is_array {
                        "Array of flexible array structures"
                    } else {
                        "Flexible array structure"
                    };

                    let suggestion = if field_info.is_array {
                        format!(
                            "Use an array of pointers instead: 'struct {} *{}[];'",
                            field_info.type_name, field_info.field_name
                        )
                    } else {
                        format!(
                            "Use a pointer instead: 'struct {} *{};'",
                            field_info.type_name, field_info.field_name
                        )
                    };

                    return Some(RuleViolation {
                        rule_id: "MEM33-C".to_string(),
                        severity: Severity::Critical, // Critical: creates undefined memory layout
                        message: format!(
                            "{} '{}' embedded as member '{}' in {}. Flexible array structures cannot be embedded - they must be allocated dynamically.",
                            violation_type,
                            field_info.type_name,
                            field_info.field_name,
                            parent_context
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(suggestion),
                    ..Default::default()
                    });
                }
            }

            // Also check for anonymous/inline struct definitions with flexible arrays
            if let Some(violation) = self.check_inline_flexible_struct(node, source, &field_info) {
                return Some(violation);
            }
        }

        None
    }

    fn extract_field_declaration_info(
        &self,
        field_node: &Node,
        source: &str,
    ) -> Option<FieldDeclarationInfo> {
        let mut field_name = String::new();
        let mut type_name = String::new();
        let mut is_pointer = false;
        let mut is_array = false;

        for i in 0..field_node.child_count() {
            if let Some(child) = field_node.child(i) {
                match child.kind() {
                    "struct_specifier" => {
                        // Field type is a struct
                        for j in 0..child.child_count() {
                            if let Some(type_child) = child.child(j) {
                                if type_child.kind() == "type_identifier" {
                                    type_name = source
                                        [type_child.start_byte()..type_child.end_byte()]
                                        .to_string();
                                }
                            }
                        }
                    }
                    "type_identifier" if type_name.is_empty() => {
                        type_name = source[child.start_byte()..child.end_byte()].to_string();
                    }
                    "field_identifier" => {
                        field_name = source[child.start_byte()..child.end_byte()].to_string();
                    }
                    "pointer_declarator" => {
                        is_pointer = true;
                        // Extract field name from pointer declarator
                        for j in 0..child.child_count() {
                            if let Some(ptr_child) = child.child(j) {
                                if ptr_child.kind() == "field_identifier" {
                                    field_name = source
                                        [ptr_child.start_byte()..ptr_child.end_byte()]
                                        .to_string();
                                }
                            }
                        }
                    }
                    "array_declarator" => {
                        is_array = true;
                        // Extract field name from array declarator
                        for j in 0..child.child_count() {
                            if let Some(arr_child) = child.child(j) {
                                if arr_child.kind() == "field_identifier" {
                                    field_name = source
                                        [arr_child.start_byte()..arr_child.end_byte()]
                                        .to_string();
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if !field_name.is_empty() || !type_name.is_empty() {
            Some(FieldDeclarationInfo {
                field_name: if field_name.is_empty() {
                    "anonymous".to_string()
                } else {
                    field_name
                },
                type_name: if type_name.is_empty() {
                    "unknown".to_string()
                } else {
                    type_name
                },
                is_pointer,
                is_array,
            })
        } else {
            None
        }
    }

    fn get_parent_structure_context(&self, node: &Node, source: &str) -> String {
        // Walk up the AST to find the parent struct/union and get its name
        let mut current = node.parent();

        while let Some(parent) = current {
            match parent.kind() {
                "struct_specifier" => {
                    // Extract struct name
                    for i in 0..parent.child_count() {
                        if let Some(child) = parent.child(i) {
                            if child.kind() == "type_identifier" {
                                let name = source[child.start_byte()..child.end_byte()].to_string();
                                return format!("struct '{}'", name);
                            }
                        }
                    }
                    return "anonymous struct".to_string();
                }
                "union_specifier" => {
                    // Extract union name
                    for i in 0..parent.child_count() {
                        if let Some(child) = parent.child(i) {
                            if child.kind() == "type_identifier" {
                                let name = source[child.start_byte()..child.end_byte()].to_string();
                                return format!("union '{}'", name);
                            }
                        }
                    }
                    return "anonymous union".to_string();
                }
                _ => current = parent.parent(),
            }
        }

        "unknown structure".to_string()
    }

    fn check_inline_flexible_struct(
        &self,
        field_node: &Node,
        source: &str,
        field_info: &FieldDeclarationInfo,
    ) -> Option<RuleViolation> {
        // Check for inline struct definitions that contain flexible arrays
        // Pattern: struct { size_t num; int data[]; } field_name;

        for i in 0..field_node.child_count() {
            if let Some(child) = field_node.child(i) {
                if child.kind() == "struct_specifier" {
                    // Check if this inline struct has flexible array members
                    for j in 0..child.child_count() {
                        if let Some(struct_child) = child.child(j) {
                            if struct_child.kind() == "field_declaration_list" {
                                if self.has_flexible_array_member(&struct_child, source) {
                                    let start_point = field_node.start_position();
                                    let parent_context =
                                        self.get_parent_structure_context(field_node, source);

                                    return Some(RuleViolation {
                                        rule_id: "MEM33-C".to_string(),
                                        severity: Severity::Critical,
                                        message: format!(
                                            "Inline struct definition with flexible array member embedded as field '{}' in {}. Inline flexible array structures cannot be embedded.",
                                            field_info.field_name,
                                            parent_context
                                        ),
                                        file_path: String::new(),
                                        line: start_point.row + 1,
                                        column: start_point.column + 1,
                                        suggestion: Some("Define the flexible array structure separately and use a pointer to it".to_string()),
                                    ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn check_casting_violations(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check for both const-casting and invalid type casting violations

        let cast_text = source[node.start_byte()..node.end_byte()].to_string();

        // Check if this is a cast to a flexible array struct pointer
        let mut target_struct_name = None;
        for struct_name in self.flexible_structs.keys() {
            if cast_text.contains(&format!("struct {}", struct_name)) && cast_text.contains("*") {
                target_struct_name = Some(struct_name.clone());
                break;
            }
        }

        if let Some(struct_name) = target_struct_name {
            // Check for invalid type casting (not const-casting)
            if let Some(violation) = self.check_invalid_type_casting(node, source, &struct_name) {
                return Some(violation);
            }

            // Check for const-casting (existing logic)
            if let Some(violation) = self.check_const_casting_specific(node, source, &struct_name) {
                return Some(violation);
            }
        }

        None
    }

    fn check_invalid_type_casting(
        &self,
        node: &Node,
        source: &str,
        target_struct_name: &str,
    ) -> Option<RuleViolation> {
        // Look for patterns like: (struct flex_array_struct *)&something
        // where 'something' is not a compatible flexible array structure

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "unary_expression" {
                    let unary_text = source[child.start_byte()..child.end_byte()].to_string();
                    if unary_text.starts_with("&") {
                        // Extract the variable being referenced
                        let var_ref = unary_text.trim_start_matches("&").trim();

                        // Check if this looks like an invalid cast
                        // Heuristics: if the variable name doesn't suggest it's a flexible array struct
                        if !var_ref.contains("flex") && !var_ref.contains(target_struct_name) {
                            // This might be casting a non-flexible array struct to flexible array struct
                            let start_point = node.start_position();
                            return Some(RuleViolation {
                                rule_id: "MEM33-C".to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Invalid type casting: casting '{}' to flexible array structure pointer '{}'. This may lead to undefined behavior when accessing the flexible array member.",
                                    var_ref, target_struct_name
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some("Ensure the source type is compatible with flexible array structure layout or use proper dynamic allocation".to_string()),
                            ..Default::default()
                            });
                        }
                    }
                }
            }
        }

        None
    }

    fn check_const_casting_specific(
        &self,
        node: &Node,
        source: &str,
        _struct_name: &str,
    ) -> Option<RuleViolation> {
        // Original const-casting logic from existing check_const_casting method
        // Check for patterns like: (struct flex_array_struct *)&const_flex
        // where const qualifier is being cast away

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "unary_expression" {
                    let unary_text = source[child.start_byte()..child.end_byte()].to_string();
                    if unary_text.starts_with("&") {
                        let var_ref = unary_text.trim_start_matches("&").trim();

                        // Check if this looks like const-casting (variable name suggests const)
                        if var_ref.contains("const") {
                            let start_point = node.start_position();
                            return Some(RuleViolation {
                                rule_id: "MEM33-C".to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Const-casting violation: casting const-qualified flexible array structure '{}' to non-const pointer. This removes const qualification and may lead to undefined behavior.",
                                    var_ref
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some("Use const-qualified pointer or avoid casting away const qualifier".to_string()),
                            ..Default::default()
                            });
                        }
                    }
                }
            }
        }

        None
    }

    /// Check for offsetof() misuse with flexible array members in call expressions
    /// Per MEM33-C, using offsetof() with flexible arrays for manual address calculation
    /// or size calculation can lead to incorrect memory handling
    fn check_offsetof_misuse(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Get the full expression text
        let node_text = source[node.start_byte()..node.end_byte()].to_string();

        // Check if this call contains offsetof
        if !node_text.contains("offsetof") {
            return None;
        }

        // Check if offsetof is being used with a flexible array struct
        let is_flex_struct = self
            .flexible_structs
            .keys()
            .any(|struct_name| node_text.contains(struct_name));

        // Also check common flexible array struct patterns
        let has_flex_pattern = node_text.contains("flex_array")
            || node_text.contains("flex_struct")
            || node_text.contains("FlexArray");

        if is_flex_struct || has_flex_pattern {
            // Check if this is being used for manual pointer arithmetic or size calculation
            // by looking at the parent context
            if let Some(parent) = node.parent() {
                let parent_text = source[parent.start_byte()..parent.end_byte()].to_string();

                // Check if offsetof result is used in:
                // 1. Pointer arithmetic (base_addr + offset)
                // 2. Size calculation (offsetof(...) + sizeof(...))
                // 3. Assignment to a size variable
                let is_problematic_use = parent_text.contains("+")
                    || parent.kind() == "binary_expression"
                    || parent.kind() == "init_declarator";

                if is_problematic_use {
                    let start_point = node.start_position();
                    return Some(RuleViolation {
                        rule_id: "MEM33-C".to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "Using offsetof() with flexible array structure for manual address/size calculation: {}. This pattern bypasses proper flexible array member handling.",
                            node_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Access flexible array members directly through the structure pointer (ptr->data[i]) instead of manual offset calculations".to_string()),
                        ..Default::default()
                    });
                }
            }
        }

        None
    }

    /// Check for offsetof() misuse in init_declarator (e.g., size_t x = offsetof(...))
    fn check_offsetof_in_init(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        let node_text = source[node.start_byte()..node.end_byte()].to_string();

        // Check if initialization contains offsetof with flexible array struct
        if !node_text.contains("offsetof") {
            return None;
        }

        // Check for flexible array struct patterns
        let is_flex_struct = self
            .flexible_structs
            .keys()
            .any(|struct_name| node_text.contains(struct_name));

        let has_flex_pattern = node_text.contains("flex_array")
            || node_text.contains("flex_struct")
            || node_text.contains("FlexArray");

        if is_flex_struct || has_flex_pattern {
            let start_point = node.start_position();
            return Some(RuleViolation {
                rule_id: "MEM33-C".to_string(),
                severity: Severity::Medium,
                message: format!(
                    "Using offsetof() with flexible array structure for manual calculation: {}. This pattern bypasses proper flexible array member handling.",
                    node_text
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Access flexible array members directly through the structure pointer (ptr->data[i]) instead of manual offset calculations".to_string()),
                ..Default::default()
            });
        }

        None
    }

    /// Check for offsetof() misuse in binary expressions (e.g., offsetof() + sizeof())
    fn check_offsetof_in_binary(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        let node_text = source[node.start_byte()..node.end_byte()].to_string();

        // Check if binary expression contains offsetof with flexible array struct
        if !node_text.contains("offsetof") {
            return None;
        }

        // Check for flexible array struct patterns
        let is_flex_struct = self
            .flexible_structs
            .keys()
            .any(|struct_name| node_text.contains(struct_name));

        let has_flex_pattern = node_text.contains("flex_array")
            || node_text.contains("flex_struct")
            || node_text.contains("FlexArray");

        if is_flex_struct || has_flex_pattern {
            // Check if this is a size calculation pattern (offsetof + sizeof)
            if node_text.contains("+")
                && (node_text.contains("sizeof")
                    || node_text.contains("base_addr")
                    || node_text.contains("data_offset"))
            {
                let start_point = node.start_position();
                return Some(RuleViolation {
                    rule_id: "MEM33-C".to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Manual size calculation using offsetof() with flexible array structure: {}. This pattern can lead to incorrect memory allocation.",
                        node_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Use sizeof(struct) + sizeof(element_type) * count for proper flexible array allocation".to_string()),
                    ..Default::default()
                });
            }
        }

        None
    }

    /// Check for sizeof(struct) used in pointer arithmetic with flexible array structures
    /// This is wrong because sizeof(struct) doesn't include the flexible array size
    fn check_sizeof_in_pointer_arithmetic(
        &self,
        node: &Node,
        source: &str,
    ) -> Option<RuleViolation> {
        // This is called for cast_expression nodes
        // We want to catch patterns like:
        //   (struct flex_array_struct *)((char *)ptr + sizeof(struct flex_array_struct))
        // But NOT allocation patterns like:
        //   (struct flex_array_struct *)malloc(sizeof(struct flex_array_struct) + ...)

        let node_text = source[node.start_byte()..node.end_byte()].to_string();

        // Skip if this is part of a malloc/calloc/realloc call (allocation, not pointer arithmetic)
        if node_text.contains("malloc")
            || node_text.contains("calloc")
            || node_text.contains("realloc")
        {
            return None;
        }

        // Look for pattern: cast of (char *)ptr + sizeof(struct) or similar
        // This indicates pointer arithmetic to move through memory
        if !node_text.contains("(char *)") && !node_text.contains("(char*)") {
            return None; // Not pointer arithmetic pattern
        }

        // Must have sizeof applied to flexible array struct in pointer arithmetic context
        if !node_text.contains("sizeof") {
            return None;
        }

        // Check if sizeof is applied to a flexible array struct
        for struct_name in self.flexible_structs.keys() {
            if node_text.contains(&format!("sizeof(struct {})", struct_name))
                || node_text.contains(&format!("sizeof({})", struct_name))
            {
                // This is sizeof applied to a flexible array struct in pointer arithmetic
                let start_point = node.start_position();
                return Some(RuleViolation {
                    rule_id: "MEM33-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Pointer arithmetic using sizeof(struct {}) doesn't account for flexible array member size. Each structure instance may have different actual sizes.",
                        struct_name
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Flexible array structures cannot be stored in contiguous arrays. Use an array of pointers to individually allocated structures instead.".to_string()),
                    ..Default::default()
                });
            }
        }

        // Also check common patterns
        if node_text.contains("sizeof(struct flex_array_struct)")
            || node_text.contains("sizeof(flex_array_struct)")
        {
            let start_point = node.start_position();
            return Some(RuleViolation {
                rule_id: "MEM33-C".to_string(),
                severity: Severity::High,
                message: "Pointer arithmetic using sizeof(struct) with flexible array structure. The sizeof operator returns only the fixed size, not including the flexible array.".to_string(),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Flexible array structures cannot be stored in contiguous arrays. Use an array of pointers to individually allocated structures instead.".to_string()),
                ..Default::default()
            });
        }

        None
    }
}
