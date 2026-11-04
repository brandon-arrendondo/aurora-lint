//! The names whose spelling does not pick out one object, keyed by
//! declaration.
//!
//! Value-range analysis keeps its state by name. A name that means one
//! object everywhere in a function is key enough. A name that does not is a
//! name the function declares twice (a block's `int x` that hides the
//! function's `x`, two loops that each declare `int i`, a block local that
//! hides a parameter), or a local whose name the function also uses for a
//! file-scope object (outside the local's block, or before its
//! declaration). One entry for both let an inner object's range replace the
//! outer one's: `int x = 1; { int x = 2; x = read_untrusted(); } return 100
//! / x;` divided by the inner `x`'s range. Each declaration of such a name
//! gets a key of its own (`name#id`, the [`LocalId`] of its declarator),
//! each occurrence is resolved to its declaration through the scope chain
//! (ADR-0006), and the ranges handed to a consumer at a point are the ones
//! of the declarations in scope there, under their plain names.

use super::address_taken::{declared_identifier, function_locals, LocalId};
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
    /// and the end of the scope it is declared in, ascending by id.
    bindings: HashMap<String, Vec<(LocalId, usize)>>,
    /// The declaration each occurrence of such a name refers to, by the
    /// occurrence's start byte. Missing for an occurrence that names no
    /// local (a file-scope object of the name), whose key is its name.
    occurrences: HashMap<usize, LocalId>,
    /// The parameters among them, by name.
    parameters: HashMap<String, LocalId>,
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
        // Every name a body declares, and a parameter's only when the body
        // declares it again: a parameter alone is in scope for the whole
        // body, where any occurrence of its name is it.
        let candidates: HashSet<&str> = locals
            .iter()
            .filter(|(id, name)| *id >= body.start_byte() || count[name.as_str()] > 1)
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

        // One walk of the body with its enclosing scopes on a stack
        // (outermost first), so resolving an occurrence costs the scopes
        // around it and no climb to find them.
        let declarations = ScopeDeclarations::default();
        let mut scopes: Vec<Node> = Vec::new();
        let mut innermost_first: Vec<Node> = Vec::new();
        let mut stack: Vec<(Node, usize)> = vec![(body, 0)];
        while let Some((node, depth)) = stack.pop() {
            scopes.truncate(depth);
            if node.kind() == "identifier" {
                let start = node.start_byte();
                let name = node.utf8_text(source.as_bytes()).unwrap_or("");
                if declared.contains(&start) {
                    // A declarator's own name: in scope to the end of the
                    // innermost scope around it.
                    let end = scopes.last().map_or(body.end_byte(), |s| s.end_byte());
                    scope_end.insert(start, end);
                    names.occurrences.insert(start, start);
                } else if let Some(&name) = candidates.get(name) {
                    innermost_first.clear();
                    innermost_first.extend(scopes.iter().rev().copied());
                    let local = declarations
                        .find_declaration_in_scope_chain(&innermost_first, start, name, source)
                        .and_then(|decl| declaration_declarator_for(&decl, name, source))
                        .and_then(|declarator| declared_identifier(&declarator))
                        .map(|ident| ident.start_byte())
                        .filter(|id| declared.contains(id))
                        .or_else(|| parameter.get(name).copied());
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
            let mut cursor = node.walk();
            let children: Vec<Node> = node.named_children(&mut cursor).collect();
            stack.extend(children.into_iter().rev().map(|c| (c, child_depth)));
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
                Cow::Owned(keyed(name, local))
            }
            _ => Cow::Borrowed(name),
        }
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

    /// The declaration of `name` in scope at `offset`: the latest declared
    /// of those whose scope holds it, which is the innermost, since scopes
    /// nest.
    fn in_scope(&self, name: &str, offset: usize) -> Option<LocalId> {
        self.bindings
            .get(name)?
            .iter()
            .filter(|&&(id, end)| id <= offset && offset < end)
            .map(|&(id, _)| id)
            .next_back()
    }

    /// Ranges by key, as the analysis keeps them, as the ranges by name a
    /// consumer reads at `offset`: each name's declaration in scope there,
    /// and none of the others. A name with no declaration in scope keeps
    /// its plain entry (a file-scope object of that name); one with a
    /// declaration in scope never does, range or not.
    pub fn view(&self, keyed_ranges: VarRangeMap, offset: usize) -> VarRangeMap {
        if self.is_empty() {
            return keyed_ranges;
        }
        let mut ranges = VarRangeMap::with_capacity(keyed_ranges.len());
        let mut scoped = Vec::new();
        for (key, range) in keyed_ranges {
            match split_key(&key) {
                Some((name, id)) => {
                    if self.in_scope(name, offset) == Some(id) {
                        scoped.push((name.to_string(), range));
                    }
                }
                None => {
                    ranges.insert(key, range);
                }
            }
        }
        for name in self.bindings.keys() {
            if self.in_scope(name, offset).is_some() {
                ranges.remove(name.as_str());
            }
        }
        ranges.extend(scoped);
        ranges
    }
}

fn keyed(name: &str, id: LocalId) -> String {
    format!("{name}{SEPARATOR}{id}")
}

fn split_key(key: &str) -> Option<(&str, LocalId)> {
    let (name, id) = key.rsplit_once(SEPARATOR)?;
    Some((name, id.parse().ok()?))
}
