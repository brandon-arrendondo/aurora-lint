//! Control-flow graph construction from tree-sitter AST.
#![allow(dead_code)]
//!
//! Builds a lightweight CFG from C function bodies. Each basic block contains
//! a sequence of statements with a single entry and single exit. Edges represent
//! control flow between blocks (fallthrough, branches, back edges, returns).

use super::const_eval::MacroConstantMap;
use super::noreturn;
use crate::utility::cert_c::ast_utils::{IdentifierBinding, ScopeDeclarations};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Unique identifier for a basic block within a function CFG.
pub type BlockId = usize;

/// A basic block: a straight-line sequence of statements.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// This block's index in the owning [`FunctionCfg`]'s `blocks` vector.
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
    /// `continue`: to a `while` loop's header, a `for` loop's update, or a
    /// `do` loop's condition block.
    Continue,
    /// Goto jump to a labeled statement.
    Goto,
}

/// Where a function-like macro's replacement list can send control when it
/// is invoked as a statement: `goto label;` or `return ...;` inside the macro
/// body (mbedtls's `ARIA_SELF_TEST_ASSERT(cond)` is `do { if (cond) { ...;
/// goto exit; } } while (0)`, `MBEDTLS_ASN1_CHK_ADD` returns the caller's
/// `ret`). Without this the invocation is an ordinary statement and every
/// path through it falls through, so a value that only reaches its read via
/// the macro's jump looks dead. The jump is taken to be
/// conditional -- the invocation keeps its fallthrough edge as well.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacroJump {
    /// The macro body contains `goto <label>`.
    Goto(String),
    /// The macro body contains a `return`.
    Return,
}

/// A control-flow graph for a single function.
#[derive(Debug, Clone)]
pub struct FunctionCfg {
    /// Every basic block, indexed by [`BlockId`].
    pub blocks: Vec<BasicBlock>,
    /// Edges as `(from, to, kind)` triples.
    pub edges: Vec<(BlockId, BlockId, CfgEdge)>,
    /// The function's single entry block.
    pub entry: BlockId,
    /// Blocks with no outgoing edge.
    pub exits: Vec<BlockId>,
    /// One entry per statement that invoked a [`MacroJump::Goto`] macro:
    /// the empty block the jump edge leaves from, and the invoking
    /// statement's byte range. A consumer that models what the macro body
    /// writes before it jumps (`{ rc = ERR; goto error; }`) puts those
    /// definitions in this block, so they hold on the jump path and not on
    /// the fallthrough.
    pub macro_jump_blocks: Vec<(BlockId, (usize, usize))>,
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
    /// Stack of (continue target, loop_exit), innermost last. A `do` loop's
    /// continue target is its condition block, which does not exist until
    /// the body is built, so its entry is `None` and its `continue`s wait in
    /// `do_continues`.
    loop_stack: Vec<(Option<BlockId>, BlockId)>,
    /// One list per open `do` loop, innermost last: the blocks a `continue`
    /// leaves, wired to the condition block once it is created.
    do_continues: Vec<Vec<BlockId>>,
    /// Stack of break targets, pushed by both loops and switch statements.
    /// `continue` always targets the innermost *loop* (via `loop_stack`), but
    /// `break` targets the innermost loop-or-switch, whichever is nearer
    /// lexically -- so it needs its own stack.
    break_stack: Vec<BlockId>,
    /// Label name → block ID mapping for goto edge wiring.
    label_blocks: HashMap<String, BlockId>,
    /// Stack of (case_statement node id -> its pre-allocated block) maps, one
    /// per currently-active `switch`, innermost last. Lets a `case`/`default`
    /// label encountered mid-walk -- nested inside a *different* arm's `{ }`,
    /// e.g. sqlite's vdbe.c `OP_ReopenIdx: { ... case OP_OpenRead: case
    /// OP_OpenWrite: ... }` opcode-dispatch pattern -- be recognized as
    /// physical fallthrough into that label's own block rather than folded
    /// into the enclosing arm's block as an opaque statement.
    case_block_stack: Vec<HashMap<usize, BlockId>>,
    /// Pending goto edges: (source_block, label_name) to wire after all labels are seen.
    pending_gotos: Vec<(BlockId, String)>,
    function_start_byte: usize,
    /// File-level constants (static const int, #define) for condition evaluation.
    constants: MacroConstantMap,
    /// Names of functions known not to return to their caller --
    /// a call to one of these terminates the current block exactly like a
    /// `return` statement.
    noreturn_names: HashSet<String>,
    /// Function-like macros whose body jumps (see [`MacroJump`]); an
    /// invocation as a statement gets that edge in addition to fallthrough.
    macro_jumps: HashMap<String, MacroJump>,
    /// See [`FunctionCfg::macro_jump_blocks`].
    macro_jump_blocks: Vec<(BlockId, (usize, usize))>,
    /// The trips of each `for` its header bounds to zero or one, by the
    /// loop's node id ([`counted_loop_trips`]).
    loop_trips: HashMap<usize, ForTrips>,
}

impl CfgBuilder {
    fn new(
        function_start_byte: usize,
        constants: MacroConstantMap,
        noreturn_names: HashSet<String>,
        macro_jumps: HashMap<String, MacroJump>,
    ) -> Self {
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
            do_continues: Vec::new(),
            break_stack: Vec::new(),
            label_blocks: HashMap::new(),
            case_block_stack: Vec::new(),
            pending_gotos: Vec::new(),
            function_start_byte,
            constants,
            noreturn_names,
            macro_jumps,
            macro_jump_blocks: Vec::new(),
            loop_trips: HashMap::new(),
        }
    }

    /// The jump a statement makes by invoking a macro in `macro_jumps`, if
    /// the statement is `NAME(...);` for such a NAME.
    fn macro_jump_of(&self, node: &Node, source: &str) -> Option<MacroJump> {
        if self.macro_jumps.is_empty() || node.kind() != "expression_statement" {
            return None;
        }
        let call = node.named_child(0)?;
        if call.kind() != "call_expression" {
            return None;
        }
        let callee = call.child_by_field_name("function")?;
        if callee.kind() != "identifier" {
            return None;
        }
        self.macro_jumps
            .get(callee.utf8_text(source.as_bytes()).ok()?)
            .cloned()
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
        crate::analyze::containment::checkpoint();
        match node.kind() {
            "if_statement" => self.process_if(node, source),
            "while_statement" => self.process_while(node, source),
            "for_statement" => self.process_for(node, source),
            "do_statement" => self.process_do_while(node, source),
            "switch_statement" => self.process_switch(node, source),
            "return_statement" => {
                self.add_statement(node.start_byte(), node.end_byte());
                let exit_block = self.new_block();
                self.add_edge(self.current_block, exit_block, CfgEdge::Return);
                self.current_block = self.new_block(); // Unreachable block after return
            }
            "break_statement" => {
                self.add_statement(node.start_byte(), node.end_byte());
                if let Some(&break_target) = self.break_stack.last() {
                    self.add_edge(self.current_block, break_target, CfgEdge::Break);
                }
                self.current_block = self.new_block(); // Unreachable block after break
            }
            "continue_statement" => {
                self.add_statement(node.start_byte(), node.end_byte());
                match self.loop_stack.last() {
                    Some(&(Some(target), _)) => {
                        self.add_edge(self.current_block, target, CfgEdge::Continue);
                    }
                    Some(&(None, _)) => {
                        if let Some(pending) = self.do_continues.last_mut() {
                            pending.push(self.current_block);
                        }
                    }
                    None => {}
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
            "case_statement" => self.process_nested_case_label(node, source),
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
            "expression_statement" if self.macro_jump_of(node, source).is_some() => {
                // `ASSERT_OR_GOTO(cond);` -- the macro body holds the jump.
                // Conditional by assumption, so the block both jumps and
                // falls through.
                self.add_statement(node.start_byte(), node.end_byte());
                match self.macro_jump_of(node, source) {
                    Some(MacroJump::Goto(label)) => {
                        // The jump leaves from its own empty block so the
                        // macro's writes-before-jump can be placed on that
                        // path alone (see `macro_jump_blocks`).
                        let jump_block = self.new_block();
                        self.add_edge(self.current_block, jump_block, CfgEdge::Fallthrough);
                        self.pending_gotos.push((jump_block, label));
                        self.macro_jump_blocks
                            .push((jump_block, (node.start_byte(), node.end_byte())));
                    }
                    Some(MacroJump::Return) => {
                        let exit_block = self.new_block();
                        self.add_edge(self.current_block, exit_block, CfgEdge::Return);
                    }
                    None => {}
                }
                let next = self.new_block();
                self.add_edge(self.current_block, next, CfgEdge::Fallthrough);
                self.current_block = next;
            }
            "expression_statement"
                if noreturn::is_noreturn_call_statement(node, source, &self.noreturn_names) =>
            {
                // A call to a known-noreturn function terminates this block
                // exactly like an explicit `return` -- e.g.
                // `if (!ptr) { slowpath(...); } /* unreachable fallthrough */`
                // where `slowpath` is declared `NORETURN`.
                self.add_statement(node.start_byte(), node.end_byte());
                let exit_block = self.new_block();
                self.add_edge(self.current_block, exit_block, CfgEdge::Return);
                self.current_block = self.new_block(); // Unreachable block after the call
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

        // `while (0)` never enters its body. The body is still built, so a
        // label in it stays a `goto` target, but nothing else reaches it, and
        // its end goes back to the condition as a plain fallthrough: control
        // that arrived by `goto` tests the condition once and leaves. No back
        // edge, since no pass follows another. A `case` label of a switch
        // around the loop is an entry this CFG does not wire (the switch
        // dispatches only to its own arms), so such a body keeps the entry
        // edge it reaches that label by.
        let body_node = node.child_by_field_name("body");
        let dead_body =
            const_val == Some(false) && !body_node.is_some_and(|b| case_enters_from_outside(&b));
        if !dead_body {
            self.add_edge(header_block, body_block, CfgEdge::TrueBranch);
        }
        // Skip FalseBranch for while(1) — the loop never exits via condition.
        // Exit is only reachable via break edges from the body.
        if const_val != Some(true) {
            self.add_edge(header_block, exit_block, CfgEdge::FalseBranch);
        }

        // Process body
        self.loop_stack.push((Some(header_block), exit_block));
        self.break_stack.push(exit_block);
        self.current_block = body_block;
        if let Some(body) = body_node {
            self.process_statement(&body, source);
        }
        let back = if const_val == Some(false) {
            CfgEdge::Fallthrough
        } else {
            CfgEdge::BackEdge
        };
        self.add_edge(self.current_block, header_block, back);
        self.loop_stack.pop();
        self.break_stack.pop();

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

        // A counted loop whose start, bound and step decide its trips, and
        // whose counter nothing else writes, runs its body exactly once
        // (`for (k = 0; k < 1; k++)`) or never (`k < 0`). Once: the first
        // test is true, so the header only enters the body, and the update
        // leaves the loop instead of going back. Never: as `while (0)`,
        // including the entry a `case` label of an outer switch keeps.
        let trips = self.loop_trips.get(&node.id()).copied();
        let enters = match trips {
            Some(ForTrips::Zero) => false,
            Some(ForTrips::One) => true,
            None => {
                const_val != Some(false)
                    || node
                        .child_by_field_name("body")
                        .is_some_and(|b| case_enters_from_outside(&b))
            }
        };
        let can_skip = match trips {
            Some(ForTrips::Zero) => true,
            Some(ForTrips::One) => false,
            None => const_val != Some(true),
        };
        if enters {
            self.add_edge(header_block, body_block, CfgEdge::TrueBranch);
        }
        // Skip FalseBranch for for(;;) or for(;1;) — loop only exits via break
        if can_skip {
            self.add_edge(header_block, exit_block, CfgEdge::FalseBranch);
        }

        // Process body
        self.loop_stack.push((Some(update_block), exit_block));
        self.break_stack.push(exit_block);
        self.current_block = body_block;
        if let Some(body) = node.child_by_field_name("body") {
            self.process_statement(&body, source);
        }
        self.add_edge(self.current_block, update_block, CfgEdge::Fallthrough);
        self.loop_stack.pop();
        self.break_stack.pop();

        // Update expression
        self.current_block = update_block;
        if let Some(update) = node.child_by_field_name("update") {
            self.add_statement(update.start_byte(), update.end_byte());
        }
        // A loop that never passes twice goes back to its test as a plain
        // fallthrough, as `while (0)` does.
        match trips {
            Some(ForTrips::One) => self.add_edge(update_block, exit_block, CfgEdge::Fallthrough),
            Some(ForTrips::Zero) => self.add_edge(update_block, header_block, CfgEdge::Fallthrough),
            None if const_val == Some(false) => {
                self.add_edge(update_block, header_block, CfgEdge::Fallthrough)
            }
            None => self.add_edge(update_block, header_block, CfgEdge::BackEdge),
        }

        self.current_block = exit_block;
    }

    fn process_do_while<'a>(&mut self, node: &Node<'a>, source: &str) {
        let body_block = self.new_block();
        self.add_edge(self.current_block, body_block, CfgEdge::Fallthrough);

        let exit_block = self.new_block();

        // Process body first (do-while executes body before checking
        // condition). A `continue` in the body jumps to the end of the body,
        // so it reaches the condition as the fallthrough does (C11 6.8.6.2):
        // those edges are wired once the condition block exists.
        self.loop_stack.push((None, exit_block));
        self.do_continues.push(Vec::new());
        self.break_stack.push(exit_block);
        self.current_block = body_block;
        if let Some(body) = node.child_by_field_name("body") {
            self.process_statement(&body, source);
        }
        self.loop_stack.pop();
        self.break_stack.pop();
        let continues = self.do_continues.pop().unwrap_or_default();

        // Condition block
        let cond_block = self.new_block();
        self.add_edge(self.current_block, cond_block, CfgEdge::Fallthrough);
        for from in continues {
            self.add_edge(from, cond_block, CfgEdge::Continue);
        }
        self.current_block = cond_block;

        let const_val = if let Some(condition) = node.child_by_field_name("condition") {
            self.add_statement(condition.start_byte(), condition.end_byte());
            if let Some(block) = self.blocks.get_mut(cond_block) {
                block.condition_range = Some((condition.start_byte(), condition.end_byte()));
            }
            evaluate_constant_condition(&condition, source, &self.constants)
        } else {
            None
        };

        // `do { ... } while (0)`, the statement-macro idiom, runs its body
        // once: no back edge, so no pass sees what an earlier one did.
        if const_val != Some(false) {
            self.add_edge(cond_block, body_block, CfgEdge::BackEdge);
        }
        self.add_edge(cond_block, exit_block, CfgEdge::FalseBranch);

        self.current_block = exit_block;
    }

    /// Model a `switch` statement with one block per `case`/`default` arm.
    ///
    /// Each `case_statement` node (tree-sitter-c) owns the label plus every
    /// statement up to (not including) the next `case_statement` sibling --
    /// so C's physical fallthrough (no `break`) is just "this block's exit
    /// falls through to the next case block". `break` targets the switch's
    /// join block via `break_stack`; previously the whole switch
    /// was a single opaque leaf statement, hiding any `free()`+`return`/`break`
    /// nested in a case arm from CFG-based rules like MEM01-C.
    fn process_switch<'a>(&mut self, node: &Node<'a>, source: &str) {
        let condition_block = self.current_block;
        let switch_const = if let Some(condition) = node.child_by_field_name("condition") {
            self.add_statement(condition.start_byte(), condition.end_byte());
            let inner = unwrap_parens_cfg(&condition);
            resolve_constant_operand(&inner, source, &self.constants)
        } else {
            None
        };

        let exit_block = self.new_block();
        self.break_stack.push(exit_block);

        let body = node.child_by_field_name("body");
        // Descend through any `#if`/`#ifdef`/`#elif`/`#else` wrappers around a
        // case arm -- aurora-lint has no preprocessor, so every branch is
        // modeled as reachable, same as process_preproc_conditional.
        let case_statement_nodes: Vec<Node> = body
            .map(|b| Self::collect_case_statements_in_switch_body(&b))
            .unwrap_or_default();
        // (block, this arm's constant case value if any, is_default)
        let mut case_blocks: Vec<(BlockId, Option<i64>, bool)> = Vec::new();
        for child in &case_statement_nodes {
            let case_block = self.new_block();
            let value = child.child_by_field_name("value");
            let is_default = value.is_none();
            let case_val = value.and_then(|v| {
                resolve_constant_operand(&unwrap_parens_cfg(&v), source, &self.constants)
            });
            case_blocks.push((case_block, case_val, is_default));
        }
        let has_default = case_blocks.iter().any(|(_, _, is_default)| *is_default);

        // If the switch's value is a compile-time constant, only the case(s)
        // it actually matches (or the default, if none match) are reachable
        // -- mirrors evaluate_constant_condition's dead-branch pruning for
        // if/while/for. Without this, e.g. `switch(5) { case 6: ...; default:
        // data = 5; }` looks like `data` is only conditionally initialized,
        // even though 5 can never hit the `case 6:` arm (an earlier fix follow-up).
        let reachable: Option<std::collections::HashSet<BlockId>> = switch_const.map(|sc| {
            let matched: Vec<BlockId> = case_blocks
                .iter()
                .filter(|(_, v, is_default)| !is_default && *v == Some(sc))
                .map(|(b, _, _)| *b)
                .collect();
            if !matched.is_empty() {
                matched.into_iter().collect()
            } else if let Some((default_block, _, _)) =
                case_blocks.iter().find(|(_, _, is_default)| *is_default)
            {
                std::iter::once(*default_block).collect()
            } else {
                std::collections::HashSet::new()
            }
        });

        for (case_block, _, _) in &case_blocks {
            let is_reachable = reachable.as_ref().is_none_or(|r| r.contains(case_block));
            if is_reachable {
                self.add_edge(condition_block, *case_block, CfgEdge::Fallthrough);
            }
        }

        // A `default:` arm always matches something, so the switch can never
        // skip straight to exit when one is present and the value isn't a
        // known-non-matching constant. Only add the "no case matches" edge
        // when there's no default, or the constant switch value is known and
        // provably matches nothing (an earlier fix follow-up).
        let skips_switch_entirely = match &reachable {
            Some(r) => r.is_empty(),
            None => !has_default,
        };
        if skips_switch_entirely {
            self.add_edge(condition_block, exit_block, CfgEdge::Fallthrough);
        }

        let case_id_to_block: HashMap<usize, BlockId> = case_statement_nodes
            .iter()
            .zip(case_blocks.iter())
            .map(|(n, (b, _, _))| (n.id(), *b))
            .collect();
        let case_blocks: Vec<BlockId> = case_blocks.into_iter().map(|(b, _, _)| b).collect();

        // Only arms found as *direct* children of the switch body (or through
        // a transparent preprocessor wrapper) drive this loop. An arm nested
        // inside another arm's `{ }` is reached when `process_nested_case_label`
        // encounters its node while walking that other arm's content --
        // walking it again here would duplicate every statement in it.
        let top_level: Vec<usize> = case_statement_nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| body.is_some_and(|b| Self::is_direct_switch_arm(n, &b)))
            .map(|(i, _)| i)
            .collect();

        self.case_block_stack.push(case_id_to_block);

        for (pos, &case_idx) in top_level.iter().enumerate() {
            self.current_block = case_blocks[case_idx];
            self.walk_case_arm_children(&case_statement_nodes[case_idx], source);

            // Physical fallthrough into the next top-level case arm if this
            // arm's control flow didn't already break/return/continue/goto out.
            let next_block = top_level
                .get(pos + 1)
                .map(|&ni| case_blocks[ni])
                .unwrap_or(exit_block);
            self.add_edge(self.current_block, next_block, CfgEdge::Fallthrough);
        }

        self.case_block_stack.pop();
        self.break_stack.pop();
        self.current_block = exit_block;
    }

    /// Walk one case arm's content: process each child statement, skipping
    /// the label tokens (`case`/`default`/`:`) and the case value expression.
    /// A nested `case_statement` child is handled by
    /// `process_statement`'s dispatch to `process_nested_case_label`, so it
    /// naturally hops this walk to that label's own block rather than being
    /// folded in here as an opaque statement.
    fn walk_case_arm_children(&mut self, node: &Node, source: &str) {
        let value_start = node.child_by_field_name("value").map(|v| v.start_byte());
        for j in 0..node.child_count() {
            if let Some(sub) = node.child(j) {
                if Some(sub.start_byte()) == value_start {
                    continue;
                }
                match sub.kind() {
                    "case" | "default" | ":" => continue,
                    _ => self.process_statement(&sub, source),
                }
            }
        }
    }

    /// Reached when a `case`/`default` label appears mid-arm, nested inside
    /// another arm's `{ }` -- physical fallthrough, not a normal
    /// statement (e.g. sqlite's vdbe.c `OP_ReopenIdx: { ... case OP_OpenRead:
    /// case OP_OpenWrite: ... }`). Jump this walk to the label's own
    /// pre-allocated block (looked up by node id in the innermost active
    /// switch's map) and continue walking its children from there.
    fn process_nested_case_label(&mut self, node: &Node, source: &str) {
        let Some(&target) = self
            .case_block_stack
            .last()
            .and_then(|map| map.get(&node.id()))
        else {
            // Not a label of the innermost active switch (shouldn't happen
            // for valid C, since `case`/`default` are only legal inside a
            // switch). Treat conservatively as an opaque statement rather
            // than silently dropping its content.
            self.add_statement(node.start_byte(), node.end_byte());
            return;
        };
        self.add_edge(self.current_block, target, CfgEdge::Fallthrough);
        self.current_block = target;
        self.walk_case_arm_children(node, source);
    }

    /// True if `case_node` is reached as a direct arm of `body` -- i.e.
    /// without descending into another arm's `{ }` -- transparently through
    /// any preprocessor wrapper. Used to pick the entry points for
    /// `process_switch`'s arm-walking loop; a case nested inside a sibling
    /// arm's braces still gets its own dispatch block and edge,
    /// but is walked via `process_nested_case_label`, not as its own loop
    /// iteration.
    fn is_direct_switch_arm(case_node: &Node, body: &Node) -> bool {
        let mut cur = *case_node;
        loop {
            let Some(parent) = cur.parent() else {
                return false;
            };
            if parent.id() == body.id() {
                return true;
            }
            match parent.kind() {
                "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_elifdef"
                | "preproc_else" => cur = parent,
                _ => return false,
            }
        }
    }

    /// Flatten every `case_statement`/`default` arm in a switch body into
    /// document order, transparently descending into `#if`/`#ifdef`/`#elif`/
    /// `#else` wrappers and into a case arm's own `{ }`.
    /// Without the preprocessor descent, a case label split across a
    /// preprocessor guard -- e.g. raylib's per-codec `#if SUPPORT_FILEFORMAT_*`
    /// arms in `UpdateMusicStream` -- was invisible to the CFG: its direct-child
    /// scan only matched bare `case_statement` siblings, so the reads/writes
    /// inside a guarded arm were never modeled, producing phantom dead-store
    /// false positives. Without the `{ }` descent, a case arm that wraps its
    /// locals in braces while later labels still physically fall through into
    /// it -- e.g. sqlite's vdbe.c `OP_ReopenIdx: { Db *pDb; ... case
    /// OP_OpenRead: case OP_OpenWrite: pDb = ...; ... }` -- hides those nested
    /// labels from dispatch-edge/reachability modeling entirely, and their
    /// content gets folded into the wrapping arm's block as one opaque
    /// statement, producing phantom "used uninitialized" (EXP33-C) findings
    /// for a variable that was, on that path, assigned immediately before use.
    fn collect_case_statements_in_switch_body<'a>(node: &Node<'a>) -> Vec<Node<'a>> {
        let mut out = Vec::new();
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "case_statement" => {
                        out.push(child);
                        // A case arm's own children can include a nested `{ }`
                        // (or, depending on grammar shape, a further label
                        // directly) that a later `case`/`default` physically
                        // falls through into -- recurse into this
                        // arm too, not just the switch body's direct children.
                        out.extend(Self::collect_case_statements_in_switch_body(&child));
                    }
                    "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_elifdef"
                    | "preproc_else" | "compound_statement" => {
                        out.extend(Self::collect_case_statements_in_switch_body(&child));
                    }
                    _ => {}
                }
            }
        }
        out
    }

    /// Model a `#ifdef`/`#ifndef`/`#if`/`#elif` conditional block.
    ///
    /// aurora-lint has no preprocessor (an earlier fix / macro-expansion-strategy): it cannot know
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
            macro_jump_blocks: self.macro_jump_blocks,
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
            file_scope_constant(&inner, name, source, constants).map(|v| v != 0)
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
/// `constants[name]`, unless the identifier binds to a local or a
/// parameter of that name: then it is another object (ADR-0006), and a
/// local `flag` shadowing a file-scope `static const int flag = 0;` is not
/// a constant.
fn file_scope_constant(
    ident: &Node,
    name: &str,
    source: &str,
    constants: &MacroConstantMap,
) -> Option<i64> {
    use crate::utility::cert_c::ast_utils::resolve_identifier_binding;
    let value = *constants.get(name)?;
    match resolve_identifier_binding(ident, name, source) {
        Some(IdentifierBinding::Local(_)) | Some(IdentifierBinding::Parameter(_)) => None,
        _ => Some(value),
    }
}

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
            file_scope_constant(node, name, source, constants)
        }
        _ => None,
    }
}

/// How many times a `for` loop's body runs, where the loop header alone
/// decides it. See [`for_trip_count`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForTrips {
    Zero,
    One,
}

/// The trips of every `for` in `func` that [`for_trip_count`] bounds to
/// zero or one, by node id. One pass over the function shares the work the
/// loops have in common: the function's `&name` set is read once, and the
/// counters resolve through one [`ScopeDeclarations`] for the function,
/// which reads each scope's declarations once, so a block of thousands of
/// such loops does not read the statements before each loop again.
fn counted_loop_trips<'a>(
    func: &Node<'a>,
    source: &str,
    constants: &MacroConstantMap,
) -> HashMap<usize, ForTrips> {
    let mut out = HashMap::new();
    let fors = lang_parsing_substrate::query::find_descendants_of_kind(*func, "for_statement");
    if fors.is_empty() {
        return out;
    }
    let mut addressed = None;
    let scopes = ScopeDeclarations::default();
    let mut resolve = |ident: &Node<'a>, name: &str| -> Option<IdentifierBinding<'a>> {
        scopes.resolve_identifier_binding(ident, name, source)
    };
    for node in fors {
        if let Some(trips) = for_trip_count(&node, source, constants, &mut addressed, &mut resolve)
        {
            out.insert(node.id(), trips);
        }
    }
    out
}

/// The trips of `for (k = c0; k OP c1; k += step)` when they are zero or
/// one: `c0`, `c1` and `step` constants (literals, or file-scope constants
/// as the other conditions read them), the update `k++`, `++k`, `k--`,
/// `--k`, `k += c` or `k -= c`, and the test false at `c0` (none) or true
/// at `c0` and false at `c0 + step` (one). `c0`, `c0 + step` and `c1` must
/// all lie in 0..=127, which every integer type holds, so each comparison
/// means in the counter's type what it means here: no wrap on the step
/// (`unsigned char k = 255; k < 256; k++`), no out-of-range start
/// (`unsigned char k = 256`), and no negative bound an unsigned comparison
/// would turn huge (`unsigned k; k < -1`).
///
/// The trip test comes first, so a loop that runs more than once costs only
/// its header. Then the loop must be one this answer holds for:
///
/// - The `for` parsed whole: two `for` headers in `#if` arms sharing one
///   body parse with an error or a missing body in the subtree.
/// - Every macro named among the constants has one definition in this file,
///   or definitions that agree: arms that define it differently give the
///   loop a different bound in another configuration (ADR-0010).
/// - The counter is a plain automatic local or parameter, neither `static`,
///   `volatile` nor a boolean (`k++` leaves a `bool` at 1), its type read
///   through the typedefs this file defines. A typedef the file does not
///   define, other than a standard one (`size_t`, `uint8_t`), declines. The
///   boolean test matches any type name spelling `bool` (`gboolean`,
///   `boolean_t`), which only costs an answer.
/// - The function never takes the counter's address.
/// - The body and the update never assign, step, or hand the counter to a
///   call (a function-like macro may assign its argument) or to an `asm`
///   output, and use no macro whose definition in this file spells the
///   counter (`#define RESET_K k = 0`).
/// - No label, and no `case` or `default` of a switch around the loop, is
///   in the body: control that enters there finds the counter at any value.
///
/// The write and address tests match by spelling, so a shadowing local
/// only costs the answer. Anything else is `None`: the loop keeps its back
/// edge. `addressed` holds the function's `&name` set once read, and
/// `resolve` finds the declaration a counter occurrence binds to.
fn for_trip_count<'a>(
    node: &Node<'a>,
    source: &str,
    constants: &MacroConstantMap,
    addressed: &mut Option<HashSet<String>>,
    resolve: &mut dyn FnMut(&Node<'a>, &str) -> Option<IdentifierBinding<'a>>,
) -> Option<ForTrips> {
    let text = |n: &Node| n.utf8_text(source.as_bytes()).ok();
    let init = node.child_by_field_name("initializer")?;
    let (name, start_node) = match init.kind() {
        "declaration" => {
            let mut cursor = init.walk();
            let declarators: Vec<Node> = init
                .children_by_field_name("declarator", &mut cursor)
                .collect();
            let [decl] = declarators.as_slice() else {
                return None;
            };
            if decl.kind() != "init_declarator" {
                return None;
            }
            let id = decl.child_by_field_name("declarator")?;
            if id.kind() != "identifier" {
                return None;
            }
            (text(&id)?, decl.child_by_field_name("value")?)
        }
        "assignment_expression" => {
            if text(&init.child_by_field_name("operator")?)? != "=" {
                return None;
            }
            let left = init.child_by_field_name("left")?;
            if left.kind() != "identifier" {
                return None;
            }
            (text(&left)?, init.child_by_field_name("right")?)
        }
        _ => return None,
    };
    let start_node = unwrap_parens_cfg(&start_node);
    let start = resolve_constant_operand(&start_node, source, constants)?;

    let condition_node = node.child_by_field_name("condition")?;
    let condition = unwrap_parens_cfg(&condition_node);
    if condition.kind() != "binary_expression" {
        return None;
    }
    let left_node = condition.child_by_field_name("left")?;
    let right_node = condition.child_by_field_name("right")?;
    let left = unwrap_parens_cfg(&left_node);
    let right = unwrap_parens_cfg(&right_node);
    let op = text(&condition.child_by_field_name("operator")?)?.trim();
    let (counter, bound_node, op) = if left.kind() == "identifier" && text(&left)? == name {
        (left, right, op)
    } else if right.kind() == "identifier" && text(&right)? == name {
        let flipped = match op {
            "<" => ">",
            ">" => "<",
            "<=" => ">=",
            ">=" => "<=",
            other => other,
        };
        (right, left, flipped)
    } else {
        return None;
    };
    let bound = resolve_constant_operand(&bound_node, source, constants)?;
    let holds = |v: i64| -> Option<bool> {
        Some(match op {
            "<" => v < bound,
            "<=" => v <= bound,
            ">" => v > bound,
            ">=" => v >= bound,
            "!=" => v != bound,
            "==" => v == bound,
            _ => return None,
        })
    };

    let update_node = node.child_by_field_name("update")?;
    let update = unwrap_parens_cfg(&update_node);
    let update_right = update.child_by_field_name("right");
    let (step, step_node): (i64, Option<Node>) = match update.kind() {
        "update_expression" => {
            let arg = update.child_by_field_name("argument")?;
            if arg.kind() != "identifier" || text(&arg)? != name {
                return None;
            }
            if text(&update.child_by_field_name("operator")?)? == "++" {
                (1, None)
            } else {
                (-1, None)
            }
        }
        "assignment_expression" => {
            let target = update.child_by_field_name("left")?;
            if target.kind() != "identifier" || text(&target)? != name {
                return None;
            }
            let by_node = unwrap_parens_cfg(update_right.as_ref()?);
            let by = resolve_constant_operand(&by_node, source, constants)?;
            match text(&update.child_by_field_name("operator")?)? {
                "+=" => (by, Some(by_node)),
                "-=" => (by.checked_neg()?, Some(by_node)),
                _ => return None,
            }
        }
        _ => return None,
    };

    // Every value the header compares must be one every integer type holds,
    // before either answer is given.
    let next = start.checked_add(step)?;
    if ![start, next, bound].iter().all(|v| (0..=127).contains(v)) {
        return None;
    }
    let trips = if !holds(start)? {
        ForTrips::Zero
    } else if !holds(next)? {
        ForTrips::One
    } else {
        return None;
    };

    if node.has_error() {
        return None;
    }
    let macros = FileMacros::of(source);
    let operands = [Some(start_node), Some(bound_node), step_node];
    if operands.iter().flatten().any(|operand| {
        let mut names = Vec::new();
        identifier_texts(operand, source, &mut names);
        names.iter().any(|n| macros.defined_differently(n))
    }) {
        return None;
    }

    // The counter is an automatic object only this loop header writes, and
    // not a `bool`, which `k++` leaves at 1 rather than stepping.
    match resolve(&counter, name)? {
        IdentifierBinding::Parameter(ty) => {
            if !counter_type_is_plain(&ty, &counter, source, 0) {
                return None;
            }
        }
        IdentifierBinding::Local(decl) => {
            let mut cursor = decl.walk();
            let qualified = decl.children(&mut cursor).any(|c| match c.kind() {
                "storage_class_specifier" => true,
                "type_qualifier" => text(&c).is_some_and(|t| t.trim() == "volatile"),
                _ => false,
            });
            let plain = decl
                .child_by_field_name("type")
                .and_then(|t| text(&t))
                .is_some_and(|t| counter_type_is_plain(t, &counter, source, 0));
            if qualified || !plain {
                return None;
            }
        }
        IdentifierBinding::Global(_) => return None,
    }
    if addressed.is_none() {
        let mut function = *node;
        while function.kind() != "function_definition" {
            function = function.parent()?;
        }
        let mut names = HashSet::new();
        addressed_names(&function, source, &mut names);
        *addressed = Some(names);
    }
    if addressed.as_ref().is_some_and(|names| names.contains(name)) {
        return None;
    }
    let body = node.child_by_field_name("body")?;
    if writes_name(&body, name, source) || macros.any_used_spells(&body, name, source) {
        return None;
    }
    if contains_label(&body) || case_enters_from_outside(&body) {
        return None;
    }
    Some(trips)
}

/// Whether a `labeled_statement` lies anywhere under `node`.
fn contains_label(node: &Node) -> bool {
    !lang_parsing_substrate::query::find_descendants_of_kind(*node, "labeled_statement").is_empty()
}

/// Whether `body` holds a `case` or `default` label of a switch outside it:
/// one reached from `body` without passing a `switch` that `body` itself
/// contains. A switch may enter the middle of a loop that way (Duff's
/// device), with the loop's counter at any value.
fn case_enters_from_outside(body: &Node) -> bool {
    lang_parsing_substrate::query::find_descendants_of_kind(*body, "case_statement")
        .iter()
        .any(|case| {
            let mut n = *case;
            while let Some(parent) = n.parent() {
                if parent.id() == body.id() {
                    return true;
                }
                if parent.kind() == "switch_statement" {
                    return false;
                }
                n = parent;
            }
            true
        })
}

/// Whether a counter declared with type `spelled` is a plain integer: no
/// `volatile`, not a boolean, and every type name in it one this file's
/// typedefs (read at `at`) or the standard library define as such. A
/// typedef the file does not define, other than a standard name, is not
/// known to be plain.
fn counter_type_is_plain(spelled: &str, at: &Node, source: &str, depth: usize) -> bool {
    use crate::utility::cert_c::ast_utils::typedef_definition_in_scope;
    use crate::utility::cert_c::expr_type::is_standard_typedef_name;
    if depth > 8 {
        return false;
    }
    let words = spelled
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty());
    for word in words {
        if word == "volatile" || word.contains("bool") || word.contains("Bool") {
            return false;
        }
        let keyword = matches!(
            word,
            "const"
                | "register"
                | "auto"
                | "signed"
                | "unsigned"
                | "char"
                | "short"
                | "int"
                | "long"
                | "float"
                | "double"
                | "restrict"
                | "__restrict"
        );
        if keyword || is_standard_typedef_name(word) {
            continue;
        }
        let Some(definition) = typedef_definition_in_scope(at, word, source) else {
            return false;
        };
        // The typedef's own specifiers and qualifiers, not the names it
        // declares.
        let ty = definition.child_by_field_name("type");
        let mut cursor = definition.walk();
        let spec: Vec<&str> = definition
            .children(&mut cursor)
            .filter(|c| ty == Some(*c) || c.kind() == "type_qualifier")
            .filter_map(|c| c.utf8_text(source.as_bytes()).ok())
            .collect();
        if spec.is_empty()
            || !counter_type_is_plain(&spec.join(" "), &definition, source, depth + 1)
        {
            return false;
        }
    }
    true
}

/// The text of every identifier under `node`, the node itself included.
fn identifier_texts(node: &Node, source: &str, out: &mut Vec<String>) {
    if node.kind() == "identifier" {
        if let Ok(t) = node.utf8_text(source.as_bytes()) {
            out.push(t.to_string());
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        identifier_texts(&child, source, out);
    }
}

/// Every name `&name` (through parentheses) takes the address of under
/// `node`.
fn addressed_names(node: &Node, source: &str, out: &mut HashSet<String>) {
    if node.kind() == "pointer_expression"
        && node
            .child_by_field_name("operator")
            .and_then(|o| o.utf8_text(source.as_bytes()).ok())
            == Some("&")
    {
        if let Some(arg) = node.child_by_field_name("argument") {
            let arg = unwrap_parens_cfg(&arg);
            if arg.kind() == "identifier" {
                if let Ok(t) = arg.utf8_text(source.as_bytes()) {
                    out.insert(t.to_string());
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        addressed_names(&child, source, out);
    }
}

/// Every identifier spelled `name` under `node`, the node itself included.
fn named_identifiers<'a>(node: &Node<'a>, name: &str, source: &str, out: &mut Vec<Node<'a>>) {
    if node.kind() == "identifier" && node.utf8_text(source.as_bytes()).ok() == Some(name) {
        out.push(*node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        named_identifiers(&child, name, source, out);
    }
}

/// The nearest ancestor of `ident` that is not a parenthesized expression,
/// with the node directly under it.
fn through_parens<'a>(ident: &Node<'a>) -> Option<(Node<'a>, Node<'a>)> {
    let mut child = *ident;
    let mut parent = child.parent()?;
    while parent.kind() == "parenthesized_expression" {
        child = parent;
        parent = child.parent()?;
    }
    Some((parent, child))
}

/// Whether anything under `node` assigns `name`, steps it, hands it to a
/// call as an argument of its own (a function-like macro may assign it), or
/// names it as an `asm` output.
fn writes_name(node: &Node, name: &str, source: &str) -> bool {
    let mut found = Vec::new();
    named_identifiers(node, name, source, &mut found);
    found.iter().any(|ident| {
        let Some((parent, child)) = through_parens(ident) else {
            return false;
        };
        match parent.kind() {
            "assignment_expression" => parent.child_by_field_name("left") == Some(child),
            "update_expression" => true,
            "argument_list" => true,
            "gnu_asm_output_operand" => true,
            _ => false,
        }
    })
}

/// The `#define`s of one source file, read from its text by lines (a
/// `\`-continued definition is one), so a definition in any `#if` arm is
/// read, and one inside a dead arm only costs an answer.
struct FileMacros {
    /// Each macro's replacement lists, one per definition, with the
    /// identifiers each spells apart from its parameters.
    by_name: HashMap<String, Vec<(String, HashSet<String>)>>,
}

type FileMacrosMemo = Option<((usize, usize), std::rc::Rc<FileMacros>)>;

thread_local! {
    /// [`FileMacros::of`] for the source last asked about on this thread.
    static FILE_MACROS: std::cell::RefCell<FileMacrosMemo> = const { std::cell::RefCell::new(None) };
}

impl FileMacros {
    /// The macros `source` defines, read once per source buffer per thread.
    fn of(source: &str) -> std::rc::Rc<FileMacros> {
        let key = (source.as_ptr() as usize, source.len());
        if let Some(found) = FILE_MACROS.with(|memo| {
            memo.borrow()
                .as_ref()
                .filter(|(k, _)| *k == key)
                .map(|(_, m)| std::rc::Rc::clone(m))
        }) {
            return found;
        }
        let read = std::rc::Rc::new(Self::read(source));
        FILE_MACROS.with(|memo| *memo.borrow_mut() = Some((key, std::rc::Rc::clone(&read))));
        read
    }

    fn read(source: &str) -> FileMacros {
        let words = |t: &str| -> Vec<String> {
            t.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|w| w.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
                .map(str::to_string)
                .collect()
        };
        let mut by_name: HashMap<String, Vec<(String, HashSet<String>)>> = HashMap::new();
        let mut lines = source.lines();
        while let Some(line) = lines.next() {
            let Some(rest) = line.trim_start().strip_prefix('#') else {
                continue;
            };
            let Some(rest) = rest.trim_start().strip_prefix("define") else {
                continue;
            };
            if !rest.starts_with([' ', '\t']) {
                continue;
            }
            let mut logical = rest.trim_start().to_string();
            while logical.ends_with('\\') {
                logical.pop();
                match lines.next() {
                    Some(next) => {
                        logical.push(' ');
                        logical.push_str(next);
                    }
                    None => break,
                }
            }
            let name_end = logical
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(logical.len());
            let name = logical[..name_end].to_string();
            if name.is_empty() {
                continue;
            }
            let after = &logical[name_end..];
            let (params, replacement) = match after.strip_prefix('(') {
                Some(list) => match list.find(')') {
                    Some(close) => (words(&list[..close]), &list[close + 1..]),
                    None => continue,
                },
                None => (Vec::new(), after),
            };
            let replacement = replacement.trim().to_string();
            let spells = words(&replacement)
                .into_iter()
                .filter(|w| !params.contains(w))
                .collect();
            by_name.entry(name).or_default().push((replacement, spells));
        }
        FileMacros { by_name }
    }

    /// Whether `name` is a macro with two definitions whose replacement
    /// lists differ.
    fn defined_differently(&self, name: &str) -> bool {
        self.by_name
            .get(name)
            .is_some_and(|defs| defs.iter().any(|(r, _)| *r != defs[0].0))
    }

    /// Whether an identifier under `node` names a macro some definition of
    /// which spells `counter` outside its parameters.
    fn any_used_spells(&self, node: &Node, counter: &str, source: &str) -> bool {
        let writers: HashSet<&str> = self
            .by_name
            .iter()
            .filter(|(_, defs)| defs.iter().any(|(_, spells)| spells.contains(counter)))
            .map(|(n, _)| n.as_str())
            .collect();
        if writers.is_empty() {
            return false;
        }
        let mut names = Vec::new();
        identifier_texts(node, source, &mut names);
        names.iter().any(|n| writers.contains(n.as_str()))
    }
}

/// Unwrap parenthesized_expression nodes for CFG condition evaluation.
fn unwrap_parens_cfg<'t>(node: &Node<'t>) -> Node<'t> {
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
/// Does not model any noreturn-call terminations -- callers that have a
/// whole-file AST available and want that (the main analysis driver) should
/// use [`build_function_cfg_with_constants_and_noreturn`] instead.
pub fn build_function_cfg_with_constants(
    func_node: &Node,
    source: &str,
    constants: &MacroConstantMap,
) -> Option<FunctionCfg> {
    build_function_cfg_with_constants_and_noreturn(func_node, source, constants, &HashSet::new())
}

/// Same as [`build_function_cfg_with_constants`], additionally treating a
/// call to any function named in `noreturn_names` as terminating its block
/// like a `return` statement. `noreturn_names` is normally
/// [`noreturn::collect_noreturn_function_names`] run once per file.
pub fn build_function_cfg_with_constants_and_noreturn(
    func_node: &Node,
    source: &str,
    constants: &MacroConstantMap,
    noreturn_names: &HashSet<String>,
) -> Option<FunctionCfg> {
    build_function_cfg_full(
        func_node,
        source,
        constants,
        noreturn_names,
        &HashMap::new(),
    )
}

/// Same as [`build_function_cfg_with_constants_and_noreturn`], additionally
/// giving a statement that invokes a macro named in `macro_jumps` the edge
/// that macro's body takes (a `goto` to its label, or a return), on top of
/// its fallthrough. See [`MacroJump`].
pub fn build_function_cfg_full(
    func_node: &Node,
    source: &str,
    constants: &MacroConstantMap,
    noreturn_names: &HashSet<String>,
    macro_jumps: &HashMap<String, MacroJump>,
) -> Option<FunctionCfg> {
    if func_node.kind() != "function_definition" {
        return None;
    }

    let body = func_node.child_by_field_name("body")?;
    if body.kind() != "compound_statement" {
        return None;
    }

    let mut builder = CfgBuilder::new(
        func_node.start_byte(),
        constants.clone(),
        noreturn_names.clone(),
        macro_jumps.clone(),
    );
    builder.loop_trips = counted_loop_trips(func_node, source, constants);
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
        // an earlier fix: a `return;` nested inside a `#ifdef`-gated block must still
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

    /// A case arm can wrap its locals in `{ }` while a later `case` label
    /// still falls through into it -- e.g. sqlite's vdbe.c `OP_ReopenIdx: {
    /// Db *pDb; ... case OP_OpenRead: case OP_OpenWrite: pDb = ...; }`
    /// opcode-dispatch pattern. Both the nested label's dispatch
    /// edge from the switch condition and the physical fallthrough edge from
    /// the wrapping arm must be modeled, and its content must land in its
    /// own block rather than being folded into the wrapping arm's block as
    /// one opaque statement.
    #[test]
    fn test_switch_case_nested_in_sibling_braces() {
        let code = r#"
        static int run(int op, int iDb) {
            switch (op) {
                case 1: {
                    int pDb;
                    if (op == 2) {
                        goto later;
                    }
                case 3:
                case 4:
                    pDb = iDb;
                    int pX = pDb;
                    return pX;
                }
            }
        later:
            return 0;
        }
        "#;
        let cfg = parse_and_build_cfg(code).unwrap();
        let condition_block = cfg.entry;

        // The nested `case 3`/`case 4` labels each got their own block with
        // a direct dispatch edge from the switch condition.
        let dispatch_targets: Vec<BlockId> = cfg
            .successors(condition_block)
            .into_iter()
            .filter(|(_, e)| **e == CfgEdge::Fallthrough)
            .map(|(id, _)| id)
            .collect();
        assert!(
            dispatch_targets.len() >= 3,
            "expected direct dispatch edges to case 1, case 3, and case 4: {:?}",
            cfg.edges
        );

        // The block containing `pDb = iDb;` also contains the very next
        // statement (`int pX = pDb;`) rather than that statement having been
        // folded into a sibling arm's block as one opaque span.
        let assign_block = cfg
            .blocks
            .iter()
            .find(|b| {
                b.statements
                    .iter()
                    .any(|&(s, e)| code[s..e].trim() == "pDb = iDb;")
            })
            .expect("pDb assignment should be modeled as its own statement");
        assert!(
            assign_block
                .statements
                .iter()
                .any(|&(s, e)| code[s..e].trim() == "int pX = pDb;"),
            "the read of pDb should be in the same block as its preceding assignment: {:?}",
            assign_block.statements
        );
    }

    /// The blocks whose condition is `cond` as written (parentheses
    /// included), in the order they were built.
    fn blocks_with_condition(cfg: &FunctionCfg, code: &str, cond: &str) -> Vec<BlockId> {
        cfg.blocks
            .iter()
            .filter(|b| b.condition_range.is_some_and(|(s, e)| &code[s..e] == cond))
            .map(|b| b.id)
            .collect()
    }

    /// The only block whose condition is `cond`.
    fn block_with_condition(cfg: &FunctionCfg, code: &str, cond: &str) -> BlockId {
        let found = blocks_with_condition(cfg, code, cond);
        assert_eq!(
            found.len(),
            1,
            "one block has condition {cond}: {:?}",
            cfg.blocks
        );
        found[0]
    }

    /// The block holding the statement `stmt`, the only one so written.
    fn block_with_statement(cfg: &FunctionCfg, code: &str, stmt: &str) -> BlockId {
        cfg.blocks
            .iter()
            .find(|b| b.statements.iter().any(|&(s, e)| code[s..e].trim() == stmt))
            .unwrap_or_else(|| panic!("no block holds {stmt}: {:?}", cfg.blocks))
            .id
    }

    /// Where the `n`th `continue;` in the source (from 0) sends control.
    fn continue_target(cfg: &FunctionCfg, code: &str, n: usize) -> BlockId {
        let at = code
            .match_indices("continue;")
            .nth(n)
            .expect("that many continues")
            .0;
        let from = cfg
            .blocks
            .iter()
            .find(|b| b.statements.iter().any(|&(s, _)| s == at))
            .expect("the continue is in a block")
            .id;
        let targets: Vec<BlockId> = cfg
            .edges
            .iter()
            .filter(|(f, _, e)| *f == from && *e == CfgEdge::Continue)
            .map(|(_, t, _)| *t)
            .collect();
        assert_eq!(
            targets.len(),
            1,
            "one continue edge from {from}: {:?}",
            cfg.edges
        );
        targets[0]
    }

    /// A `continue` in a `do` body goes to the condition (C11 6.8.6.2), so
    /// the condition is tested on that path and the loop exit is reached
    /// from it, not to the body.
    #[test]
    fn a_continue_in_a_do_body_goes_to_the_condition() {
        let code = "void f(int c, int k) { do { if (c) continue; g(); } while (k); h(); }";
        let cfg = parse_and_build_cfg(code).unwrap();
        let cond = block_with_condition(&cfg, code, "(k)");
        assert_eq!(continue_target(&cfg, code, 0), cond);
        let body = block_with_condition(&cfg, code, "(c)");
        assert!(
            cfg.edges.contains(&(cond, body, CfgEdge::BackEdge)),
            "the back edge still enters the body: {:?}",
            cfg.edges
        );
        assert!(
            !cfg.edges
                .iter()
                .any(|(_, t, e)| *t == body && *e == CfgEdge::Continue),
            "no continue enters the body: {:?}",
            cfg.edges
        );
    }

    /// Each `continue` targets its own innermost loop, and a `break` in a
    /// `switch` inside the `do` leaves only the switch.
    #[test]
    fn continues_in_nested_loops_and_a_switch_target_their_own_loop() {
        let code = "void f(int a, int b, int k, int x) {
            do {
                for (int i = 0; i < a; i++) { if (b) continue; g(); }
                while (a) { if (b) continue; a--; }
                switch (x) { case 1: continue; case 2: break; }
                h();
            } while (k);
            while (x) { do { continue; } while (a); x--; continue; }
        }";
        let cfg = parse_and_build_cfg(code).unwrap();
        let do_cond = block_with_condition(&cfg, code, "(k)");
        let for_update = block_with_statement(&cfg, code, "i++");
        // `while (a)` is built before the inner `do ... while (a)`.
        let [while_a, inner_do_cond] = blocks_with_condition(&cfg, code, "(a)")[..] else {
            panic!("two blocks test (a): {:?}", cfg.blocks)
        };
        let while_x = block_with_condition(&cfg, code, "(x)");
        assert_eq!(continue_target(&cfg, code, 0), for_update);
        assert_eq!(continue_target(&cfg, code, 1), while_a);
        assert_eq!(
            continue_target(&cfg, code, 2),
            do_cond,
            "case 1 continues the do loop"
        );
        assert_eq!(continue_target(&cfg, code, 3), inner_do_cond);
        assert_eq!(continue_target(&cfg, code, 4), while_x);
        let do_exit = cfg
            .edges
            .iter()
            .find(|(f, _, e)| *f == do_cond && *e == CfgEdge::FalseBranch)
            .map(|(_, t, _)| *t)
            .expect("the do loop exits from its condition");
        assert!(
            cfg.edges
                .iter()
                .all(|(_, t, e)| *e != CfgEdge::Break || *t != do_exit),
            "the switch's break leaves the switch, not the do loop: {:?}",
            cfg.edges
        );
    }

    fn has_back_edge(code: &str) -> bool {
        let cfg = parse_and_build_cfg(code).unwrap();
        cfg.edges.iter().any(|(_, _, e)| *e == CfgEdge::BackEdge)
    }

    /// Whether the block holding `stmt` is reachable from the entry.
    fn reaches(code: &str, stmt: &str) -> bool {
        let cfg = parse_and_build_cfg(code).unwrap();
        let target = block_with_statement(&cfg, code, stmt);
        let mut seen = HashSet::from([cfg.entry]);
        let mut work = vec![cfg.entry];
        while let Some(b) = work.pop() {
            for (succ, _) in cfg.successors(b) {
                if seen.insert(succ) {
                    work.push(succ);
                }
            }
        }
        seen.contains(&target)
    }

    /// `do { ... } while (0)` runs its body once: no pass follows another.
    #[test]
    fn a_do_while_zero_has_no_back_edge() {
        assert!(!has_back_edge(
            "void f(int fd) { do { g(fd); } while (0); }"
        ));
        assert!(has_back_edge(
            "void f(int fd, int a) { do { g(fd); } while (a); }"
        ));
    }

    /// `while (0)` never enters its body, and the loop has no back edge,
    /// while a label in the body is still a `goto` target.
    #[test]
    fn a_while_zero_body_is_dead() {
        let code = "void f(int fd) { while (0) { g(fd); } h(fd); }";
        assert!(!has_back_edge(code));
        assert!(!reaches(code, "g(fd);"));
        assert!(reaches(code, "h(fd);"));
        let jumped = "void f(int fd) { goto in; while (0) { in: g(fd); } h(fd); }";
        assert!(reaches(jumped, "g(fd);"));
        assert!(!has_back_edge(jumped));
    }

    /// A counted `for` that its header proves runs once has no back edge
    /// and cannot skip its body; one that never runs has a dead body.
    #[test]
    fn a_for_its_header_proves_single_pass_has_no_back_edge() {
        let once = "void f(int fd) { int k; for (k = 0; k < 1; k++) { g(fd); } }";
        assert!(!has_back_edge(once));
        assert!(reaches(once, "g(fd);"));
        let cfg = parse_and_build_cfg(once).unwrap();
        let header = block_with_condition(&cfg, once, "k < 1");
        assert!(
            !cfg.successors(header)
                .iter()
                .any(|(_, e)| **e == CfgEdge::FalseBranch),
            "the first test is true: {:?}",
            cfg.edges
        );
        for code in [
            "void f(int fd) { for (int k = 0; k < 1; k++) { g(fd); } }",
            "void f(int fd) { for (int k = 0; 1 > k; ++k) { g(fd); } }",
            "void f(int fd) { for (int k = 3; k >= 3; k--) { g(fd); } }",
            "void f(int fd) { for (int k = 0; k != 4; k += 4) { g(fd); } }",
        ] {
            assert!(!has_back_edge(code), "{code}");
        }
        let never = "void f(int fd) { for (int k = 0; k < 0; k++) { g(fd); } h(fd); }";
        assert!(!has_back_edge(never));
        assert!(!reaches(never, "g(fd);"));
        assert!(reaches(never, "h(fd);"));
    }

    /// A loop the header does not bound to one pass keeps its back edge:
    /// a second trip, a counter the body writes or hands to a call, one
    /// whose address is taken, a `static`, `volatile`, `bool` or file-scope
    /// counter, a bound that is not constant, a value a narrow type may wrap,
    /// a label a `goto` may enter the body by.
    #[test]
    fn a_for_not_proved_single_pass_keeps_its_back_edge() {
        for code in [
            "void f(int fd) { for (int k = 0; k < 2; k++) { g(fd); } }",
            "void f(int fd) { for (int k = 0; k < 1; k++) { g(fd); k--; } }",
            "void f(int fd) { for (int k = 0; k < 1; k++) { g(fd); k = 0; } }",
            "void f(int fd) { for (int k = 0; k < 1; k++) { RESET(k); } }",
            "void f(int fd) { int k; int *p = &k; for (k = 0; k < 1; k++) { *p = 0; } }",
            "void f(int fd) { static int k; for (k = 0; k < 1; k++) { g(fd); } }",
            "int k; void f(int fd) { for (k = 0; k < 1; k++) { g(fd); } }",
            "void f(int fd, int n) { for (int k = 0; k < n; k++) { g(fd); } }",
            "void f(int fd) { for (int k = 0; k++ < 1; k++) { g(fd); } }",
            "void f(int fd) { for (_Bool k = 1; k < 2; k++) { g(fd); } }",
            "void f(int fd) { for (unsigned char k = 255; k < 256; k++) { g(fd); } }",
            "void f(int fd) { for (int k = 0; k < 1; k++) { in: g(fd); } goto in; }",
            "void f(int fd) { volatile int k; for (k = 0; k < 1; k++) { g(fd); } }",
        ] {
            assert!(has_back_edge(code), "{code}");
        }
    }

    fn cfg_with(code: &str, constants: &[(&str, i64)]) -> FunctionCfg {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let root = tree.root_node();
        let mut cursor = root.walk();
        let func = root
            .children(&mut cursor)
            .find(|c| c.kind() == "function_definition")
            .unwrap();
        let constants: MacroConstantMap =
            constants.iter().map(|(n, v)| (n.to_string(), *v)).collect();
        build_function_cfg_with_constants(&func, code, &constants).unwrap()
    }

    fn back_edges(cfg: &FunctionCfg) -> usize {
        cfg.edges
            .iter()
            .filter(|(_, _, e)| *e == CfgEdge::BackEdge)
            .count()
    }

    /// The header's constants decide the trips only where every value it
    /// compares is one each integer type holds: a negative bound an
    /// unsigned counter is compared against, or a start a narrow counter
    /// wraps, leaves the loop as it was, body live and back edge kept.
    #[test]
    fn a_for_header_out_of_the_shared_range_decides_nothing() {
        for code in [
            "void f(int *p) { unsigned k; for (k = 0; k < -1; k++) { g(p); } }",
            "void f(int *p) { unsigned k; for (k = 0; k < (-1); k++) { g(p); } }",
            "void f(int *p) { unsigned k; for (k = 0; k < NEGC; k++) { g(p); } }",
            "void f(int *p) { unsigned char k; for (k = 256; k < 1; k++) { g(p); } }",
            "void f(int *p) { int k; for (k = 0; k > 5; k--) { g(p); } }",
        ] {
            let cfg = cfg_with(code, &[("NEGC", -1)]);
            assert!(back_edges(&cfg) > 0, "{code}");
            assert!(reaches(code, "g(p);"), "{code}");
        }
        // Inside the range the answers stand.
        let never = "void f(int *p) { int k; for (k = 5; k < 3; k++) { g(p); } }";
        assert!(!reaches(never, "g(p);"));
        let once = "void f(int *p) { int k; for (k = 0; k < ONE; k++) { g(p); } }";
        assert_eq!(back_edges(&cfg_with(once, &[("ONE", 1)])), 0);
    }

    /// A `case` label of a switch around the loop enters the body with the
    /// counter at any value: a dead `while (0)` or `for` body stays
    /// reachable through it, and a one-pass `for` keeps its back edge. A
    /// switch inside the body owns its own labels and changes nothing.
    #[test]
    fn a_case_label_of_an_outer_switch_enters_the_loop_body() {
        let while0 =
            "void f(int *p, int x) { switch (x) { case 0: while (0) { case 1: g(p); } } h(p); }";
        assert!(reaches(while0, "case 1: g(p);"));
        assert!(!has_back_edge(while0));
        let dead_for = "void f(int *p, int x) { int k = 0; switch (x) { case 0: for (k = 0; k < 0; k++) { case 1: g(p); } } h(p); }";
        assert!(reaches(dead_for, "case 1: g(p);"));
        let duff = "void f(int *p, int x) { int k = -5; switch (x) { case 0: for (k = 0; k < 1; k++) { case 1: g(p); } } }";
        assert!(has_back_edge(duff));
        let dflt = "void f(int *p, int x) { int k = -5; switch (x) { case 0: for (k = 0; k < 1; k++) { default: g(p); } } }";
        assert!(has_back_edge(dflt));
        // Its own switch's labels do not enter the loop from outside.
        let own = "void f(int *p, int x) { int k; for (k = 0; k < 1; k++) { switch (x) { case 1: g(p); break; default: break; } } }";
        assert!(!has_back_edge(own));
        let own_dead = "void f(int *p, int x) { while (0) { switch (x) { case 1: g(p); } } h(p); }";
        assert!(!reaches(own_dead, "g(p);"));
        assert!(reaches(own_dead, "h(p);"));
    }

    /// A counter written where the body's own tree does not show it: by a
    /// macro whose definition spells it, through a typedef that hides
    /// `volatile` or `_Bool`, or as an `asm` output. Each loop runs more than
    /// once, so each keeps its back edge. A macro that does not spell the
    /// counter, and a typedef the file shows to be a plain integer, do not
    /// cost the answer.
    #[test]
    fn a_counter_written_out_of_sight_keeps_the_back_edge() {
        for code in [
            "#define RESET_K k = 0\nvoid f(int *p) { int k; for (k = 0; k < 1; k++) { g(p); RESET_K; } }",
            "#define BUMP() (k--)\nvoid f(int *p) { int k; for (k = 0; k < 1; k++) { g(p); BUMP(); } }",
            "typedef volatile int vint;\nvoid f(int *p) { vint k; for (k = 0; k < 1; k++) { g(p); } }",
            "typedef volatile int vint; typedef vint vv;\nvoid f(int *p) { vv k; for (k = 0; k < 1; k++) { g(p); } }",
            "typedef _Bool flag_t;\nvoid f(int *p) { flag_t k; for (k = 1; k < 2; k++) { g(p); } }",
            "typedef volatile int vint;\nvoid f(int *p, vint k) { for (k = 0; k < 1; k++) { g(p); } }",
            "void f(int *p) { int k; for (k = 0; k < 1; k++) { g(p); __asm__ volatile (\"\" : \"=r\"(k)); } }",
            "void f(int *p) { counter_t k; for (k = 0; k < 1; k++) { g(p); } }",
        ] {
            assert!(has_back_edge(code), "{code}");
        }
        for code in [
            "#define LOG() g(p)\nvoid f(int *p) { int k; for (k = 0; k < 1; k++) { LOG(); } }",
            "#define SET(k) ((k) = 0)\nvoid f(int *p) { int k, m; for (k = 0; k < 1; k++) { SET(m); } }",
            "typedef int myint;\nvoid f(int *p) { myint k; for (k = 0; k < 1; k++) { g(p); } }",
            "void f(int *p) { size_t k; for (k = 0; k < 1; k++) { g(p); } }",
            "void f(int *p) { uint8_t k; for (k = 0; k < 1; k++) { g(p); } }",
        ] {
            assert!(!has_back_edge(code), "{code}");
        }
    }

    /// A bound macro the file defines differently in two arms bounds the
    /// loop differently in another configuration, so neither answer holds
    /// for every build. Definitions that agree are one bound.
    #[test]
    fn a_bound_macro_defined_differently_across_arms_decides_nothing() {
        let differ = "#if defined(A)\n#define M 1\n#else\n#define M 3\n#endif\nvoid f(int *p) { int k; for (k = 0; k < M; k++) { g(p); } }";
        assert!(back_edges(&cfg_with(differ, &[("M", 1)])) > 0);
        let agree = "#if defined(A)\n#define M 1\n#else\n#define M 1\n#endif\nvoid f(int *p) { int k; for (k = 0; k < M; k++) { g(p); } }";
        assert_eq!(back_edges(&cfg_with(agree, &[("M", 1)])), 0);
    }

    /// Two `for` headers in `#ifdef`/`#else` arms sharing the body after
    /// `#endif` parse with a missing body; neither header decides the trips.
    #[test]
    fn for_headers_in_preprocessor_arms_sharing_a_body_decide_nothing() {
        let code = "void f(int *p)\n{\n    int k;\n#ifdef WIDE\n    for (k = 0; k < 4; k++)\n#else\n    for (k = 0; k < 1; k++)\n#endif\n    { g(p); }\n}\n";
        assert_eq!(back_edges(&parse_and_build_cfg(code).unwrap()), 2);
    }

    /// A `for` whose condition is the constant 0 never passes twice: the
    /// update goes back to the test without a back edge.
    #[test]
    fn a_for_with_a_false_condition_has_no_back_edge() {
        let code = "void f(int *p) { int k; for (k = 0; 0; k++) { g(p); } h(p); }";
        assert!(!has_back_edge(code));
        assert!(!reaches(code, "g(p);"));
        assert!(reaches(code, "h(p);"));
    }
}
