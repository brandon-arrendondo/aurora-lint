//! Control-flow graph construction from tree-sitter AST.
#![allow(dead_code)]
//!
//! Builds a lightweight CFG from C function bodies. Each basic block contains
//! a sequence of statements with a single entry and single exit. Edges represent
//! control flow between blocks (fallthrough, branches, back edges, returns).

use super::const_eval::MacroConstantMap;
use std::collections::HashMap;
use tree_sitter::Node;

/// Unique identifier for a basic block within a function CFG.
pub type BlockId = usize;

/// A basic block: a straight-line sequence of statements.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    /// Byte ranges of statements in this block (start, end).
    pub statements: Vec<(usize, usize)>,
    /// Overall byte range of this block.
    pub byte_range: (usize, usize),
    /// Byte range of the condition expression (for if/while/for/do-while blocks).
    /// Used by null-state analysis to extract edge refinement info.
    pub condition_range: Option<(usize, usize)>,
}

/// Edge types in the control-flow graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgEdge {
    /// Sequential fallthrough to the next block.
    Fallthrough,
    /// True branch of an if/while/for condition.
    TrueBranch,
    /// False branch of an if/while/for condition.
    FalseBranch,
    /// Back edge from loop body to loop header.
    BackEdge,
    /// Return from function (edge to exit block).
    Return,
    /// Break out of a loop.
    Break,
    /// Continue to loop header.
    Continue,
    /// Goto jump to a labeled statement.
    Goto,
}

/// A control-flow graph for a single function.
#[derive(Debug, Clone)]
pub struct FunctionCfg {
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<(BlockId, BlockId, CfgEdge)>,
    pub entry: BlockId,
    pub exits: Vec<BlockId>,
    /// Source code for the function (for extracting text).
    function_start_byte: usize,
}

impl FunctionCfg {
    /// Get successors of a block.
    pub fn successors(&self, block_id: BlockId) -> Vec<(BlockId, &CfgEdge)> {
        self.edges
            .iter()
            .filter(|(from, _, _)| *from == block_id)
            .map(|(_, to, edge)| (*to, edge))
            .collect()
    }

    /// Get predecessors of a block.
    pub fn predecessors(&self, block_id: BlockId) -> Vec<(BlockId, &CfgEdge)> {
        self.edges
            .iter()
            .filter(|(_, to, _)| *to == block_id)
            .map(|(from, _, edge)| (*from, edge))
            .collect()
    }

    /// Get the number of blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Get a block by ID.
    pub fn get_block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.get(id)
    }
}

/// Builder for constructing a CFG from a function's compound_statement body.
struct CfgBuilder {
    blocks: Vec<BasicBlock>,
    edges: Vec<(BlockId, BlockId, CfgEdge)>,
    current_block: BlockId,
    /// Stack of (loop_header, loop_exit) for break/continue targets.
    loop_stack: Vec<(BlockId, BlockId)>,
    /// Label name → block ID mapping for goto edge wiring.
    label_blocks: HashMap<String, BlockId>,
    /// Pending goto edges: (source_block, label_name) to wire after all labels are seen.
    pending_gotos: Vec<(BlockId, String)>,
    function_start_byte: usize,
    /// File-level constants (static const int, #define) for condition evaluation.
    constants: MacroConstantMap,
}

impl CfgBuilder {
    fn new(function_start_byte: usize, constants: MacroConstantMap) -> Self {
        let entry_block = BasicBlock {
            id: 0,
            statements: Vec::new(),
            byte_range: (0, 0),
            condition_range: None,
        };
        CfgBuilder {
            blocks: vec![entry_block],
            edges: Vec::new(),
            current_block: 0,
            loop_stack: Vec::new(),
            label_blocks: HashMap::new(),
            pending_gotos: Vec::new(),
            function_start_byte,
            constants,
        }
    }

    fn new_block(&mut self) -> BlockId {
        let id = self.blocks.len();
        self.blocks.push(BasicBlock {
            id,
            statements: Vec::new(),
            byte_range: (0, 0),
            condition_range: None,
        });
        id
    }

    fn add_edge(&mut self, from: BlockId, to: BlockId, kind: CfgEdge) {
        // Avoid duplicate edges
        if !self
            .edges
            .iter()
            .any(|(f, t, k)| *f == from && *t == to && *k == kind)
        {
            self.edges.push((from, to, kind));
        }
    }

    fn add_statement(&mut self, start: usize, end: usize) {
        if let Some(block) = self.blocks.get_mut(self.current_block) {
            block.statements.push((start, end));
            if block.byte_range.0 == 0 || start < block.byte_range.0 {
                block.byte_range.0 = start;
            }
            if end > block.byte_range.1 {
                block.byte_range.1 = end;
            }
        }
    }

    fn build_from_compound_statement<'a>(&mut self, node: &Node<'a>, source: &str) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "{" | "}" => continue,
                    _ => self.process_statement(&child, source),
                }
            }
        }
    }

    fn process_statement<'a>(&mut self, node: &Node<'a>, source: &str) {
        match node.kind() {
            "if_statement" => self.process_if(node, source),
            "while_statement" => self.process_while(node, source),
            "for_statement" => self.process_for(node, source),
            "do_statement" => self.process_do_while(node, source),
            "switch_statement" => {
                // Treat switch as a single statement for now
                self.add_statement(node.start_byte(), node.end_byte());
            }
            "return_statement" => {
                self.add_statement(node.start_byte(), node.end_byte());
                let exit_block = self.new_block();
                self.add_edge(self.current_block, exit_block, CfgEdge::Return);
                self.current_block = self.new_block(); // Unreachable block after return
            }
            "break_statement" => {
                self.add_statement(node.start_byte(), node.end_byte());
                if let Some(&(_, loop_exit)) = self.loop_stack.last() {
                    self.add_edge(self.current_block, loop_exit, CfgEdge::Break);
                }
                self.current_block = self.new_block(); // Unreachable block after break
            }
            "continue_statement" => {
                self.add_statement(node.start_byte(), node.end_byte());
                if let Some(&(loop_header, _)) = self.loop_stack.last() {
                    self.add_edge(self.current_block, loop_header, CfgEdge::Continue);
                }
                self.current_block = self.new_block(); // Unreachable block after continue
            }
            "goto_statement" => {
                self.add_statement(node.start_byte(), node.end_byte());
                // Extract label name and record for deferred edge wiring
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "statement_identifier" || child.kind() == "identifier" {
                            if let Ok(label) = child.utf8_text(source.as_bytes()) {
                                self.pending_gotos
                                    .push((self.current_block, label.to_string()));
                            }
                        }
                    }
                }
                self.current_block = self.new_block(); // Unreachable block after goto
            }
            "compound_statement" => {
                self.build_from_compound_statement(node, source);
            }
            "preproc_ifdef" | "preproc_ifndef" | "preproc_if" => {
                self.process_preproc_conditional(node, source);
            }
            "labeled_statement" => {
                // Start a new block at the label — goto edges target this block
                let label_block = self.new_block();
                self.add_edge(self.current_block, label_block, CfgEdge::Fallthrough);
                self.current_block = label_block;

                // Record label name → block mapping
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "identifier" || child.kind() == "statement_identifier" {
                            if let Ok(label) = child.utf8_text(source.as_bytes()) {
                                self.label_blocks.insert(label.to_string(), label_block);
                            }
                        }
                    }
                }

                // Process the labeled statement's body
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() != ":"
                            && child.kind() != "identifier"
                            && child.kind() != "statement_identifier"
                        {
                            self.process_statement(&child, source);
                        }
                    }
                }
            }
            _ => {
                // Regular statement: add to current block
                self.add_statement(node.start_byte(), node.end_byte());
            }
        }
    }

    fn process_if<'a>(&mut self, node: &Node<'a>, source: &str) {
        // Add the condition to the current block and check for constant value
        let const_val = if let Some(condition) = node.child_by_field_name("condition") {
            self.add_statement(condition.start_byte(), condition.end_byte());
            if let Some(block) = self.blocks.get_mut(self.current_block) {
                block.condition_range = Some((condition.start_byte(), condition.end_byte()));
            }
            evaluate_constant_condition(&condition, source, &self.constants)
        } else {
            None
        };

        let condition_block = self.current_block;
        let then_block = self.new_block();
        let join_block = self.new_block();

        // True branch — skip if condition is constant false
        if const_val != Some(false) {
            self.add_edge(condition_block, then_block, CfgEdge::TrueBranch);
            self.current_block = then_block;

            if let Some(consequence) = node.child_by_field_name("consequence") {
                self.process_statement(&consequence, source);
            }
            self.add_edge(self.current_block, join_block, CfgEdge::Fallthrough);
        }

        // False branch — skip if condition is constant true
        if const_val != Some(true) {
            if let Some(alternative) = node.child_by_field_name("alternative") {
                let else_block = self.new_block();
                self.add_edge(condition_block, else_block, CfgEdge::FalseBranch);
                self.current_block = else_block;

                // else_clause has a child that is the actual statement
                for i in 0..alternative.child_count() {
                    if let Some(child) = alternative.child(i) {
                        if child.kind() != "else" {
                            self.process_statement(&child, source);
                        }
                    }
                }
                self.add_edge(self.current_block, join_block, CfgEdge::Fallthrough);
            } else {
                self.add_edge(condition_block, join_block, CfgEdge::FalseBranch);
            }
        }

        // If condition is constant, ensure join block is reachable from exactly one side.
        // When the constant makes one branch dead AND there's no else, connect directly.
        if const_val == Some(false) && node.child_by_field_name("alternative").is_none() {
            self.add_edge(condition_block, join_block, CfgEdge::Fallthrough);
        }

        self.current_block = join_block;
    }

    fn process_while<'a>(&mut self, node: &Node<'a>, source: &str) {
        let header_block = self.new_block();
        self.add_edge(self.current_block, header_block, CfgEdge::Fallthrough);

        // Add condition to header block
        self.current_block = header_block;
        let const_val = if let Some(condition) = node.child_by_field_name("condition") {
            self.add_statement(condition.start_byte(), condition.end_byte());
            if let Some(block) = self.blocks.get_mut(header_block) {
                block.condition_range = Some((condition.start_byte(), condition.end_byte()));
            }
            evaluate_constant_condition(&condition, source, &self.constants)
        } else {
            None
        };

        let body_block = self.new_block();
        let exit_block = self.new_block();

        self.add_edge(header_block, body_block, CfgEdge::TrueBranch);
        // Skip FalseBranch for while(1) — the loop never exits via condition.
        // Exit is only reachable via break edges from the body.
        if const_val != Some(true) {
            self.add_edge(header_block, exit_block, CfgEdge::FalseBranch);
        }

        // Process body
        self.loop_stack.push((header_block, exit_block));
        self.current_block = body_block;
        if let Some(body) = node.child_by_field_name("body") {
            self.process_statement(&body, source);
        }
        self.add_edge(self.current_block, header_block, CfgEdge::BackEdge);
        self.loop_stack.pop();

        self.current_block = exit_block;
    }

    fn process_for<'a>(&mut self, node: &Node<'a>, source: &str) {
        // Initializer in current block
        if let Some(initializer) = node.child_by_field_name("initializer") {
            self.add_statement(initializer.start_byte(), initializer.end_byte());
        }

        let header_block = self.new_block();
        self.add_edge(self.current_block, header_block, CfgEdge::Fallthrough);

        // Condition in header block — for(;;) has no condition (always-true)
        self.current_block = header_block;
        let const_val = if let Some(condition) = node.child_by_field_name("condition") {
            self.add_statement(condition.start_byte(), condition.end_byte());
            if let Some(block) = self.blocks.get_mut(header_block) {
                block.condition_range = Some((condition.start_byte(), condition.end_byte()));
            }
            evaluate_constant_condition(&condition, source, &self.constants)
        } else {
            // No condition = for(;;) = always true
            Some(true)
        };

        let body_block = self.new_block();
        let update_block = self.new_block();
        let exit_block = self.new_block();

        self.add_edge(header_block, body_block, CfgEdge::TrueBranch);
        // Skip FalseBranch for for(;;) or for(;1;) — loop only exits via break
        if const_val != Some(true) {
            self.add_edge(header_block, exit_block, CfgEdge::FalseBranch);
        }

        // Process body
        self.loop_stack.push((update_block, exit_block));
        self.current_block = body_block;
        if let Some(body) = node.child_by_field_name("body") {
            self.process_statement(&body, source);
        }
        self.add_edge(self.current_block, update_block, CfgEdge::Fallthrough);
        self.loop_stack.pop();

        // Update expression
        self.current_block = update_block;
        if let Some(update) = node.child_by_field_name("update") {
            self.add_statement(update.start_byte(), update.end_byte());
        }
        self.add_edge(update_block, header_block, CfgEdge::BackEdge);

        self.current_block = exit_block;
    }

    fn process_do_while<'a>(&mut self, node: &Node<'a>, source: &str) {
        let body_block = self.new_block();
        self.add_edge(self.current_block, body_block, CfgEdge::Fallthrough);

        let exit_block = self.new_block();

        // Process body first (do-while executes body before checking condition)
        self.loop_stack.push((body_block, exit_block));
        self.current_block = body_block;
        if let Some(body) = node.child_by_field_name("body") {
            self.process_statement(&body, source);
        }
        self.loop_stack.pop();

        // Condition block
        let cond_block = self.new_block();
        self.add_edge(self.current_block, cond_block, CfgEdge::Fallthrough);
        self.current_block = cond_block;

        if let Some(condition) = node.child_by_field_name("condition") {
            self.add_statement(condition.start_byte(), condition.end_byte());
            if let Some(block) = self.blocks.get_mut(cond_block) {
                block.condition_range = Some((condition.start_byte(), condition.end_byte()));
            }
        }

        self.add_edge(cond_block, body_block, CfgEdge::BackEdge);
        self.add_edge(cond_block, exit_block, CfgEdge::FalseBranch);

        self.current_block = exit_block;
    }

    /// Model a `#ifdef`/`#ifndef`/`#if`/`#elif` conditional block.
    ///
    /// sqc has no preprocessor (task 319 / macro-expansion-strategy): it cannot know
    /// which branch of a conditional-compilation directive would actually be
    /// compiled, so both the consequence and any `#else`/`#elif` alternative must be
    /// modeled as reachable, forking/joining CFG paths — exactly like an `if` with a
    /// non-constant condition. Previously this node kind fell through to the
    /// catch-all "opaque statement" arm, which swallowed any `return`/`free`/etc.
    /// nested inside the directive: the CFG never saw them as separate statements,
    /// so control flow appeared to fall straight through into the code that
    /// followed the `#endif` (e.g. a `return;` guarding an early `free()` was
    /// invisible, making MEM01-C believe the pointer was freed again by an
    /// unconditional `free()` later in the same function).
    fn process_preproc_conditional<'a>(&mut self, node: &Node<'a>, source: &str) {
        let entry_block = self.current_block;
        let condition = node.child_by_field_name("condition");
        let condition_start = condition.map(|c| c.start_byte());
        let is_name_bearing = matches!(node.kind(), "preproc_ifdef" | "preproc_ifndef");

        let cons_block = self.new_block();
        self.add_edge(entry_block, cons_block, CfgEdge::Fallthrough);
        self.current_block = cons_block;

        let mut alt: Option<Node<'a>> = None;
        let mut seen_name = false;
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if condition_start == Some(child.start_byte()) {
                    continue;
                }
                match child.kind() {
                    "#ifdef" | "#ifndef" | "#if" | "#elif" | "#endif" | "comment" => continue,
                    "identifier" if is_name_bearing && !seen_name => {
                        // The macro name being tested, not a statement.
                        seen_name = true;
                    }
                    "preproc_else" | "preproc_elif" => alt = Some(child),
                    _ => self.process_statement(&child, source),
                }
            }
        }
        let cons_end = self.current_block;

        let alt_end = if let Some(alt_node) = alt {
            let alt_block = self.new_block();
            self.add_edge(entry_block, alt_block, CfgEdge::Fallthrough);
            self.current_block = alt_block;
            match alt_node.kind() {
                "preproc_elif" => self.process_preproc_conditional(&alt_node, source),
                _ => {
                    // preproc_else: no condition, just directly-nested statements.
                    for i in 0..alt_node.child_count() {
                        if let Some(child) = alt_node.child(i) {
                            match child.kind() {
                                "#else" | "comment" => continue,
                                _ => self.process_statement(&child, source),
                            }
                        }
                    }
                }
            }
            self.current_block
        } else {
            entry_block
        };

        let join_block = self.new_block();
        self.add_edge(cons_end, join_block, CfgEdge::Fallthrough);
        self.add_edge(alt_end, join_block, CfgEdge::Fallthrough);
        self.current_block = join_block;
    }

    fn build(mut self) -> FunctionCfg {
        // Wire pending goto edges now that all labels have been seen
        let goto_edges: Vec<(BlockId, BlockId)> = self
            .pending_gotos
            .iter()
            .filter_map(|(src, label)| self.label_blocks.get(label).map(|&tgt| (*src, tgt)))
            .collect();
        for (src, tgt) in goto_edges {
            self.add_edge(src, tgt, CfgEdge::Goto);
        }

        // Find exit blocks (blocks with Return edges, or the last block if it has no successors)
        let mut exits: Vec<BlockId> = self
            .edges
            .iter()
            .filter(|(_, _, kind)| *kind == CfgEdge::Return)
            .map(|(from, _, _)| *from)
            .collect();

        // Also include terminal blocks (those in Return edges as targets)
        let return_targets: Vec<BlockId> = self
            .edges
            .iter()
            .filter(|(_, _, kind)| *kind == CfgEdge::Return)
            .map(|(_, to, _)| *to)
            .collect();
        exits.extend(return_targets);

        // If no explicit returns, the last block is an implicit exit
        if exits.is_empty() && !self.blocks.is_empty() {
            exits.push(self.blocks.len() - 1);
        }

        exits.sort();
        exits.dedup();

        FunctionCfg {
            blocks: self.blocks,
            edges: self.edges,
            entry: 0,
            exits,
            function_start_byte: self.function_start_byte,
        }
    }
}

/// Evaluate whether a condition node is a compile-time constant.
/// Returns `Some(true)` for truthy constants (non-zero integer, `true`),
/// `Some(false)` for `0` / `false`, and `None` for non-constant expressions.
fn evaluate_constant_condition(
    condition: &Node,
    source: &str,
    constants: &MacroConstantMap,
) -> Option<bool> {
    // The condition field of an if/while is a parenthesized_expression in C.
    let inner = unwrap_parens_cfg(condition);
    match inner.kind() {
        "number_literal" => {
            let text = inner.utf8_text(source.as_bytes()).ok()?;
            let trimmed = text.trim();
            if trimmed == "0" {
                Some(false)
            } else {
                // Accept any integer literal that isn't 0 as truthy
                trimmed.parse::<i64>().ok().map(|n| n != 0)
            }
        }
        "true" => Some(true),
        "false" => Some(false),
        // Resolve identifiers via file-level constants (static const int, #define).
        // E.g., `static const int STATIC_CONST_TRUE = 1;` → if(STATIC_CONST_TRUE) is truthy.
        "identifier" => {
            let name = inner.utf8_text(source.as_bytes()).ok()?;
            constants.get(name).map(|&v| v != 0)
        }
        // Handle constant comparisons: 5==5, 5!=5, etc.
        "binary_expression" => {
            let left = inner.child_by_field_name("left")?;
            let operator = inner.child_by_field_name("operator")?;
            let right = inner.child_by_field_name("right")?;
            let left = unwrap_parens_cfg(&left);
            let right = unwrap_parens_cfg(&right);

            // Resolve each operand: number literal or identifier via constants
            let lv = resolve_constant_operand(&left, source, constants)?;
            let rv = resolve_constant_operand(&right, source, constants)?;

            let op = operator.utf8_text(source.as_bytes()).ok()?;
            match op.trim() {
                "==" => Some(lv == rv),
                "!=" => Some(lv != rv),
                "<" => Some(lv < rv),
                ">" => Some(lv > rv),
                "<=" => Some(lv <= rv),
                ">=" => Some(lv >= rv),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Resolve a single operand node to an i64 value (number literal or constant identifier).
fn resolve_constant_operand(
    node: &Node,
    source: &str,
    constants: &MacroConstantMap,
) -> Option<i64> {
    match node.kind() {
        "number_literal" => {
            let text = node.utf8_text(source.as_bytes()).ok()?.trim().to_string();
            text.parse::<i64>().ok()
        }
        "identifier" => {
            let name = node.utf8_text(source.as_bytes()).ok()?;
            constants.get(name).copied()
        }
        _ => None,
    }
}

/// Unwrap parenthesized_expression nodes for CFG condition evaluation.
fn unwrap_parens_cfg<'a>(node: &'a Node<'a>) -> Node<'a> {
    let mut n = *node;
    while n.kind() == "parenthesized_expression" {
        if let Some(inner) = n.child(1) {
            n = inner;
        } else {
            break;
        }
    }
    n
}

/// Build a CFG from a function_definition node.
/// Returns None if the node is not a function_definition or has no body.
pub fn build_function_cfg(func_node: &Node, source: &str) -> Option<FunctionCfg> {
    build_function_cfg_with_constants(func_node, source, &MacroConstantMap::new())
}

/// Build a CFG with file-level constant resolution (static const int, #define).
/// This enables dead-branch pruning for patterns like `if(STATIC_CONST_TRUE)`.
pub fn build_function_cfg_with_constants(
    func_node: &Node,
    source: &str,
    constants: &MacroConstantMap,
) -> Option<FunctionCfg> {
    if func_node.kind() != "function_definition" {
        return None;
    }

    let body = func_node.child_by_field_name("body")?;
    if body.kind() != "compound_statement" {
        return None;
    }

    let mut builder = CfgBuilder::new(func_node.start_byte(), constants.clone());
    builder.build_from_compound_statement(&body, source);
    Some(builder.build())
}

/// Extract the function name from a function_definition node.
pub fn get_function_name<'a>(func_node: &Node<'a>, source: &'a str) -> Option<&'a str> {
    let declarator = func_node.child_by_field_name("declarator")?;
    extract_name_from_declarator(&declarator, source)
}

fn extract_name_from_declarator<'a>(node: &Node<'a>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" => node.utf8_text(source.as_bytes()).ok(),
        "function_declarator" | "pointer_declarator" => {
            let inner = node.child_by_field_name("declarator")?;
            extract_name_from_declarator(&inner, source)
        }
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        return child.utf8_text(source.as_bytes()).ok();
                    }
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_build_cfg(code: &str) -> Option<FunctionCfg> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let root = tree.root_node();

        // Find the function_definition
        for i in 0..root.child_count() {
            if let Some(child) = root.child(i) {
                if child.kind() == "function_definition" {
                    return build_function_cfg(&child, code);
                }
            }
        }
        None
    }

    #[test]
    fn test_simple_function() {
        let code = r#"
        void foo() {
            int x = 1;
            int y = 2;
        }
        "#;
        let cfg = parse_and_build_cfg(code).unwrap();
        assert!(cfg.block_count() >= 1);
        assert_eq!(cfg.entry, 0);
    }

    #[test]
    fn test_if_else() {
        let code = r#"
        void foo(int x) {
            if (x > 0) {
                x = 1;
            } else {
                x = 2;
            }
            x = 3;
        }
        "#;
        let cfg = parse_and_build_cfg(code).unwrap();
        // Should have: entry, then-block, else-block, join-block (minimum)
        assert!(cfg.block_count() >= 4);
        // Should have true and false branch edges
        let has_true = cfg.edges.iter().any(|(_, _, e)| *e == CfgEdge::TrueBranch);
        let has_false = cfg.edges.iter().any(|(_, _, e)| *e == CfgEdge::FalseBranch);
        assert!(has_true);
        assert!(has_false);
    }

    #[test]
    fn test_while_loop() {
        let code = r#"
        void foo(int n) {
            int i = 0;
            while (i < n) {
                i++;
            }
        }
        "#;
        let cfg = parse_and_build_cfg(code).unwrap();
        // Should have a back edge
        let has_back = cfg.edges.iter().any(|(_, _, e)| *e == CfgEdge::BackEdge);
        assert!(has_back);
    }

    #[test]
    fn test_for_loop() {
        let code = r#"
        void foo() {
            for (int i = 0; i < 10; i++) {
                int x = i;
            }
        }
        "#;
        let cfg = parse_and_build_cfg(code).unwrap();
        let has_back = cfg.edges.iter().any(|(_, _, e)| *e == CfgEdge::BackEdge);
        assert!(has_back);
    }

    #[test]
    fn test_return_creates_exit() {
        let code = r#"
        int foo(int x) {
            if (x < 0) {
                return -1;
            }
            return x;
        }
        "#;
        let cfg = parse_and_build_cfg(code).unwrap();
        let return_count = cfg
            .edges
            .iter()
            .filter(|(_, _, e)| *e == CfgEdge::Return)
            .count();
        assert!(return_count >= 2);
    }

    #[test]
    fn test_goto_edges() {
        let code = r#"
        void foo(int x) {
            if (x < 0) goto skip;
            int y = 42;
            skip:
            use(y);
        }
        "#;
        let cfg = parse_and_build_cfg(code).unwrap();
        let has_goto = cfg.edges.iter().any(|(_, _, e)| *e == CfgEdge::Goto);
        assert!(has_goto, "Should have a goto edge");
        // The label should create a new block
        assert!(
            cfg.block_count() >= 4,
            "goto+label should create at least 4 blocks"
        );
    }

    #[test]
    fn test_preproc_ifdef_return_is_a_real_exit() {
        // task 319: a `return;` nested inside a `#ifdef`-gated block must still
        // terminate the CFG path — it must not silently fall through into code
        // that follows the `#endif`.
        let code = r#"
        void foo(int bad, char *reply) {
        #ifdef CONFIG_CTRL_IFACE_UDP
            if (bad) {
                free(reply);
                return;
            }
        #endif
            free(reply);
        }
        "#;
        let cfg = parse_and_build_cfg(code).unwrap();

        // The block containing the inner free() must have a Return edge out of it
        // (not a Fallthrough straight into the block with the outer free()).
        let inner_free_byte = code.find("free(reply);\n                return").unwrap();
        let inner_block = cfg
            .blocks
            .iter()
            .find(|b| {
                b.statements
                    .iter()
                    .any(|&(s, e)| inner_free_byte >= s && inner_free_byte < e)
            })
            .expect("inner free() should be modeled as its own statement");

        let has_return_edge = cfg
            .successors(inner_block.id)
            .iter()
            .any(|(_, e)| **e == CfgEdge::Return);
        assert!(
            has_return_edge,
            "block containing the guarded free() must exit via Return, not fall through: {:?}",
            cfg.edges
        );

        // The block should NOT have a Fallthrough edge directly into whatever
        // block holds the outer, unconditional free() (the old bug's symptom).
        let outer_free_byte = code.rfind("free(reply);").unwrap();
        let outer_block_id = cfg
            .blocks
            .iter()
            .find(|b| {
                b.statements
                    .iter()
                    .any(|&(s, e)| outer_free_byte >= s && outer_free_byte < e)
            })
            .map(|b| b.id)
            .expect("outer free() should be modeled as its own statement");
        let falls_through_to_outer = cfg
            .successors(inner_block.id)
            .iter()
            .any(|(id, e)| *id == outer_block_id && **e == CfgEdge::Fallthrough);
        assert!(
            !falls_through_to_outer,
            "guarded free()+return must not fall through into the outer free(): {:?}",
            cfg.edges
        );
    }

    #[test]
    fn test_break_continue() {
        let code = r#"
        void foo(int n) {
            for (int i = 0; i < n; i++) {
                if (i == 5) break;
                if (i == 3) continue;
            }
        }
        "#;
        let cfg = parse_and_build_cfg(code).unwrap();
        let has_break = cfg.edges.iter().any(|(_, _, e)| *e == CfgEdge::Break);
        let has_continue = cfg.edges.iter().any(|(_, _, e)| *e == CfgEdge::Continue);
        assert!(has_break);
        assert!(has_continue);
    }
}
