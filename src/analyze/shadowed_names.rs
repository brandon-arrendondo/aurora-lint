//! The names whose spelling does not pick out one object, keyed by
//! declaration.
//!
//! Value-range analysis keeps its state by name. A name that means one
//! object everywhere in a function is key enough. A name that does not is a
//! name the function declares twice (a block's `int x` that hides the
//! function's `x`, two loops that each declare `int i`, a block local that
//! hides a parameter), or a local whose name the function also uses for a
//! file-scope object (outside the local's block, before its declaration, or
//! under a block's `extern` of the name). One entry for both let an inner
//! object's range replace the outer one's: `int x = 1; { int x = 2; x =
//! read_untrusted(); } return 100 / x;` divided by the inner `x`'s range.
//! Each declaration of such a name gets a key of its own (`name#id`, the
//! [`LocalId`] of its declarator), each occurrence is resolved to its
//! declaration through the scope chain (ADR-0006), and the ranges handed to
//! a consumer at a point are the ones of the declarations in scope there,
//! under their plain names.
//!
//! The analysis reads every arm of a preprocessor conditional as a branch,
//! of which the build compiles one. Two consequences:
//!
//! - Two declarations of one name directly in one scope are one object. C
//!   allows no second definition in a scope, so a translation unit that has
//!   both has them in alternative arms (`#ifdef A int x = a(); #else int x =
//!   4; #endif`). Their ranges must meet at the join, as they do for one
//!   name assigned in each arm, so both declarations share the first's key.
//! - A declaration in one arm is not in scope in a later arm of the same
//!   conditional: in `#ifdef A int x = 4; #else x = a(); #endif` the
//!   `#else` arm assigns whatever `x` is in scope around the conditional.

use super::address_taken::{declared_identifier, function_locals, is_extern, LocalId};
use super::const_eval::VarRangeMap;
use crate::utility::cert_c::ast_utils::{
    declaration_declarator_for, is_declaration_scope, ScopeDeclarations,
};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// What separates a name from its declaration's id in a key. No identifier
/// holds it.
const SEPARATOR: char = '#';

/// One function's names that do not pick out one object, each declaration
/// with the stretch of source it is in scope for, and every occurrence of
/// those names with the declaration it refers to. Empty for a function whose
/// every name means one object, which is most of them: its keys are its
/// names.
#[derive(Debug, Default)]
pub struct ShadowedNames {
    /// For each such name, its declarations: the declarator's [`LocalId`]
    /// and the end of the scope it is declared in, ascending by id. A
    /// block's `extern` of the name is one of them: in its scope the name
    /// is the file-scope object again, whose key is its name.
    bindings: HashMap<String, Vec<(LocalId, usize)>>,
    /// The block `extern` declarations among the bindings.
    externs: HashSet<LocalId>,
    /// The declaration each occurrence of such a name refers to, by the
    /// occurrence's start byte. Missing for an occurrence that names no
    /// local (a file-scope object of the name), whose key is its name.
    occurrences: HashMap<usize, LocalId>,
    /// The parameters among them, by name.
    parameters: HashMap<String, LocalId>,
    /// A declaration of a name made again in the same scope, to the first
    /// one there, whose key both share.
    first_in_scope: HashMap<LocalId, LocalId>,
    /// For a declaration inside a preprocessor arm, the later arms of each
    /// conditional around it: stretches of its scope it is not in scope
    /// for.
    other_arms: HashMap<LocalId, Vec<(usize, usize)>>,
}

impl ShadowedNames {
    /// The names of `func`, a `function_definition`, that do not pick out
    /// one object.
    pub fn of_function(func: &Node, source: &str) -> Self {
        let mut names = ShadowedNames::default();
        let Some(body) = func.child_by_field_name("body") else {
            return names;
        };
        let locals = function_locals(func, source);
        let mut count: HashMap<&str, usize> = HashMap::new();
        for (_, name) in &locals {
            *count.entry(name.as_str()).or_default() += 1;
        }
        // A parameter a block's `extern` hides is not one object either.
        let externs = block_extern_names(&body, source);
        // Every name a body declares, and a parameter's only when the body
        // declares it again: a parameter alone is in scope for the whole
        // body, where any occurrence of its name is it.
        let candidates: HashSet<&str> = locals
            .iter()
            .filter(|(id, name)| {
                *id >= body.start_byte() || count[name.as_str()] > 1 || externs.contains(name)
            })
            .map(|(_, name)| name.as_str())
            .collect();
        if candidates.is_empty() {
            return names;
        }
        // A parameter is in scope for the whole body. A body declaration's
        // scope end is read where the walk below meets its declarator.
        let mut scope_end: HashMap<LocalId, usize> = HashMap::new();
        let mut parameter: HashMap<&str, LocalId> = HashMap::new();
        for (id, name) in &locals {
            if *id < body.start_byte() && candidates.contains(name.as_str()) {
                scope_end.insert(*id, body.end_byte());
                parameter.insert(name.as_str(), *id);
            }
        }
        let declared: HashSet<LocalId> = locals
            .iter()
            .filter(|(_, name)| candidates.contains(name.as_str()))
            .map(|&(id, _)| id)
            .collect();
        // Names some occurrence of which is no local of the function.
        let mut elsewhere: HashSet<&str> = HashSet::new();
        // The first declaration of each name directly in each scope, by the
        // scope's start byte.
        let mut first: HashMap<(usize, &str), LocalId> = HashMap::new();
        // The scope each body declaration is directly in, by start byte.
        let mut declared_in: HashMap<LocalId, usize> = HashMap::new();
        // Block `extern` declarations of a candidate: id, scope end, name.
        let mut extern_bindings: Vec<(LocalId, usize, &str)> = Vec::new();

        // One walk of the body with its enclosing scopes and preprocessor
        // arms on stacks (outermost first), so resolving an occurrence costs
        // the scopes around it and no climb to find them.
        let declarations = ScopeDeclarations::default();
        let mut scopes: Vec<Node> = Vec::new();
        let mut arms: Vec<Node> = Vec::new();
        let mut innermost_first: Vec<Node> = Vec::new();
        let mut stack: Vec<(Node, usize, usize)> = vec![(body, 0, 0)];
        while let Some((node, depth, arm_depth)) = stack.pop() {
            scopes.truncate(depth);
            arms.truncate(arm_depth);
            let innermost = scopes.last().unwrap_or(&body);
            if node.kind() == "declaration" && is_extern(&node, source) {
                let mut cursor = node.walk();
                for declarator in node.children_by_field_name("declarator", &mut cursor) {
                    let Some(ident) = declared_identifier(&declarator) else {
                        continue;
                    };
                    let name = ident.utf8_text(source.as_bytes()).unwrap_or("");
                    if let Some(&name) = candidates.get(name) {
                        extern_bindings.push((ident.start_byte(), innermost.end_byte(), name));
                    }
                }
            } else if node.kind() == "identifier" {
                let start = node.start_byte();
                let name = node.utf8_text(source.as_bytes()).unwrap_or("");
                if declared.contains(&start) {
                    // A declarator's own name: in scope to the end of the
                    // innermost scope around it, outside the later arms of
                    // each conditional it is in.
                    let id = *first.entry((innermost.start_byte(), name)).or_insert(start);
                    if id != start {
                        names.first_in_scope.insert(start, id);
                    }
                    scope_end.insert(start, innermost.end_byte());
                    declared_in.insert(start, innermost.start_byte());
                    let later: Vec<(usize, usize)> = arms
                        .iter()
                        .filter_map(|arm| later_arms(arm, start))
                        .collect();
                    if !later.is_empty() {
                        names.other_arms.insert(start, later);
                    }
                    names.occurrences.insert(start, id);
                } else if let Some(&name) = candidates.get(name) {
                    innermost_first.clear();
                    innermost_first.extend(scopes.iter().rev().copied());
                    let local = names.resolve(
                        &declarations,
                        &innermost_first,
                        start,
                        name,
                        source,
                        &declared,
                        &declared_in,
                        &parameter,
                    );
                    match local {
                        Some(id) => {
                            names.occurrences.insert(start, id);
                        }
                        None => {
                            elsewhere.insert(name);
                        }
                    }
                }
            }
            let child_depth = if is_declaration_scope(&node) {
                scopes.push(node);
                depth + 1
            } else {
                depth
            };
            let child_arm_depth = if is_arm(&node) {
                arms.push(node);
                arm_depth + 1
            } else {
                arm_depth
            };
            let mut cursor = node.walk();
            let children: Vec<Node> = node.named_children(&mut cursor).collect();
            stack.extend(
                children
                    .into_iter()
                    .rev()
                    .map(|c| (c, child_depth, child_arm_depth)),
            );
        }
        // An occurrence resolved to a declaration made again in its scope
        // refers to the first one's key.
        for id in names.occurrences.values_mut() {
            if let Some(&first) = names.first_in_scope.get(id) {
                *id = first;
            }
        }

        // A name declared once that every occurrence resolves to is one
        // object: its spelling stays its key.
        let keyed = |name: &str| count[name] > 1 || elsewhere.contains(name);
        for (id, name) in &locals {
            if let Some(&end) = scope_end.get(id) {
                if keyed(name) {
                    names
                        .bindings
                        .entry(name.clone())
                        .or_default()
                        .push((*id, end));
                }
            }
        }
        for (id, end, name) in extern_bindings {
            if let Some(declarations) = names.bindings.get_mut(name) {
                declarations.push((id, end));
                names.externs.insert(id);
            }
        }
        if names.bindings.is_empty() {
            return ShadowedNames::default();
        }
        let ids: HashSet<LocalId> = names
            .bindings
            .values()
            .flatten()
            .map(|&(id, _)| id)
            .collect();
        names.occurrences.retain(|_, id| ids.contains(id));
        names.first_in_scope.retain(|id, _| ids.contains(id));
        names.other_arms.retain(|id, _| ids.contains(id));
        names.parameters = parameter
            .into_iter()
            .filter(|(_, id)| ids.contains(id))
            .map(|(name, id)| (name.to_string(), id))
            .collect();
        for declarations in names.bindings.values_mut() {
            declarations.sort_unstable();
        }
        names
    }

    /// The local the occurrence of `name` at `start` refers to, through
    /// `innermost_first`, the scopes around it. A declaration the chain
    /// finds in an earlier arm of a conditional the occurrence is in a
    /// later arm of is not it: the search goes on outward from that
    /// declaration's scope. A declaration that is no local is a block
    /// `extern`: the file-scope object, even where a parameter of the name
    /// is in scope.
    #[allow(clippy::too_many_arguments)]
    fn resolve<'t>(
        &self,
        declarations: &ScopeDeclarations<'t>,
        innermost_first: &[Node<'t>],
        start: usize,
        name: &str,
        source: &str,
        declared: &HashSet<LocalId>,
        declared_in: &HashMap<LocalId, usize>,
        parameter: &HashMap<&str, LocalId>,
    ) -> Option<LocalId> {
        let mut from = 0;
        loop {
            let Some(decl) = declarations.find_declaration_in_scope_chain(
                &innermost_first[from..],
                start,
                name,
                source,
            ) else {
                return parameter.get(name).copied();
            };
            let id = declaration_declarator_for(&decl, name, source)
                .and_then(|declarator| declared_identifier(&declarator))
                .map(|ident| ident.start_byte())
                .filter(|id| declared.contains(id))?;
            if !self.in_other_arm(id, start) {
                return Some(id);
            }
            let scope = declared_in.get(&id)?;
            from += innermost_first[from..]
                .iter()
                .position(|s| s.start_byte() == *scope)?
                + 1;
        }
    }

    /// Whether `offset` is in a later arm of a conditional the declaration
    /// `id` is in.
    fn in_other_arm(&self, id: LocalId, offset: usize) -> bool {
        self.other_arms
            .get(&id)
            .is_some_and(|arms| arms.iter().any(|&(s, e)| s <= offset && offset < e))
    }

    /// Whether every name of the function means one object, so every key is
    /// a name.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// The key of the object `ident`, an occurrence of `name`, refers to.
    pub fn key<'n>(&self, ident: &Node, name: &'n str) -> Cow<'n, str> {
        if self.is_empty() || !self.bindings.contains_key(name) {
            return Cow::Borrowed(name);
        }
        match self.occurrences.get(&ident.start_byte()) {
            Some(&id) => Cow::Owned(keyed(name, id)),
            None => Cow::Borrowed(name),
        }
    }

    /// The key of `local`, a declaration of `name`.
    pub fn key_of_local<'n>(&self, local: LocalId, name: &'n str) -> Cow<'n, str> {
        match self.bindings.get(name) {
            Some(declarations) if declarations.iter().any(|&(id, _)| id == local) => {
                Cow::Owned(keyed(name, self.key_id(local)))
            }
            _ => Cow::Borrowed(name),
        }
    }

    /// The id in the key of the declaration `id`: the first declaration of
    /// its name in its scope.
    fn key_id(&self, id: LocalId) -> LocalId {
        self.first_in_scope.get(&id).copied().unwrap_or(id)
    }

    /// The key of the parameter `name`.
    pub fn key_of_parameter<'n>(&self, name: &'n str) -> Cow<'n, str> {
        match self.parameters.get(name) {
            Some(&id) => Cow::Owned(keyed(name, id)),
            None => Cow::Borrowed(name),
        }
    }

    /// The key of the object the declarator `declarator` declares, `name`.
    pub fn key_of_declarator<'n>(&self, declarator: &Node, name: &'n str) -> Cow<'n, str> {
        match declared_identifier(declarator) {
            Some(ident) => self.key_of_local(ident.start_byte(), name),
            None => Cow::Borrowed(name),
        }
    }

    /// The id in the key of the local declaration of `name` in scope at
    /// `offset`: the latest declared of those whose scope holds it, which is
    /// the innermost, since scopes nest. None where none is, or where the
    /// innermost is a block `extern`, under which the name is the
    /// file-scope object.
    fn in_scope(&self, name: &str, offset: usize) -> Option<LocalId> {
        let declarations = self.bindings.get(name)?;
        let before = declarations.partition_point(|&(id, _)| id <= offset);
        let id = declarations[..before]
            .iter()
            .rev()
            .find(|&&(id, end)| offset < end && !self.in_other_arm(id, offset))
            .map(|&(id, _)| id)?;
        (!self.externs.contains(&id)).then(|| self.key_id(id))
    }

    /// Ranges by key, as the analysis keeps them, as the ranges by name a
    /// consumer reads at `offset`: each name's declaration in scope there,
    /// and none of the others. A name with no local declaration in scope
    /// keeps its plain entry (a file-scope object of that name); one with a
    /// local declaration in scope never does, range or not.
    pub fn view(&self, keyed_ranges: VarRangeMap, offset: usize) -> VarRangeMap {
        if self.is_empty() {
            return keyed_ranges;
        }
        let visible: HashMap<&str, Option<LocalId>> = self
            .bindings
            .keys()
            .map(|name| (name.as_str(), self.in_scope(name, offset)))
            .collect();
        let mut ranges = VarRangeMap::with_capacity(keyed_ranges.len());
        let mut scoped = Vec::new();
        for (key, range) in keyed_ranges {
            match split_key(&key) {
                Some((name, id)) => {
                    if visible.get(name).copied().flatten() == Some(id) {
                        scoped.push((name.to_string(), range));
                    }
                }
                None => {
                    if !matches!(visible.get(key.as_str()), Some(Some(_))) {
                        ranges.insert(key, range);
                    }
                }
            }
        }
        ranges.extend(scoped);
        ranges
    }

    /// Drop from `state` every key whose declaration's scope ended at or
    /// before `offset`. Nothing from `offset` on reads it, so this changes
    /// no range a consumer sees, only what joins and copies carry: a
    /// function of many blocks each declaring the name would carry every
    /// block's entry to its end.
    pub fn forget_ended<V>(&self, state: &mut HashMap<String, V>, offset: usize) {
        if self.is_empty() {
            return;
        }
        state.retain(|key, _| {
            let Some((name, id)) = split_key(key) else {
                return true;
            };
            let Some(declarations) = self.bindings.get(name) else {
                return true;
            };
            match declarations.binary_search_by_key(&id, |&(id, _)| id) {
                Ok(i) => offset < declarations[i].1,
                Err(_) => true,
            }
        });
    }
}

/// Whether `node` is one arm of a preprocessor conditional: the `#if`,
/// `#ifdef` or `#ifndef` arm (whose node holds the rest of the conditional
/// as its `alternative`), an `#elif` arm (likewise), or the `#else` arm.
fn is_arm(node: &Node) -> bool {
    matches!(
        node.kind(),
        "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_elifdef" | "preproc_else"
    )
}

/// The later arms of `arm`'s conditional, as a stretch of source, when
/// `offset` is in `arm` itself rather than in those later arms.
fn later_arms(arm: &Node, offset: usize) -> Option<(usize, usize)> {
    let alternative = arm.child_by_field_name("alternative")?;
    (offset < alternative.start_byte()).then(|| (alternative.start_byte(), alternative.end_byte()))
}

/// The names `body` declares `extern` in a block of its own.
fn block_extern_names(body: &Node, source: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    if !source[body.byte_range()].contains("extern") {
        return names;
    }
    let mut stack = vec![*body];
    while let Some(node) = stack.pop() {
        if node.kind() == "declaration" && is_extern(&node, source) {
            let mut cursor = node.walk();
            for declarator in node.children_by_field_name("declarator", &mut cursor) {
                if let Some(ident) = declared_identifier(&declarator) {
                    names.insert(source[ident.byte_range()].to_string());
                }
            }
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    names
}

fn keyed(name: &str, id: LocalId) -> String {
    format!("{name}{SEPARATOR}{id}")
}

fn split_key(key: &str) -> Option<(&str, LocalId)> {
    let (name, id) = key.rsplit_once(SEPARATOR)?;
    Some((name, id.parse().ok()?))
}
