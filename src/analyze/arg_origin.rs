//! Where each argument a call site passes comes from, recorded per caller so
//! a rule can judge a parameter by the values its callers pass rather than by
//! whether a caller's body happens to contain a taint source.
//!
//! The record mirrors the provenance a rule reads off an expression in its own
//! function body (`int_provenance::operand_is_risky`): the callees whose result
//! reaches the argument (called in it, or assigned to or filled into a variable
//! it names), the other names it reads (a global's writers decide those), and
//! the caller's own parameters it forwards. Which callees are risky is left to
//! the rule, once every summary exists, so the same record serves any rule's
//! notion of a source.
//!
//! Collected for every direct call in every scanned function and aggregated
//! onto the callee's summary keyed by caller ([`aggregate`]). A parameter is
//! then judged by [`param_is_risky`]: the caller set must be closed and fully
//! collected, and every caller's argument must be clean, up the chain of
//! forwarded parameters. That makes a parameter's verdict the verdict its
//! argument would get if the caller's code were written inline (ADR-0011: a
//! closed set of call sites, all passing a safe argument).

use crate::analyze::context::SummaryLookup;
use crate::analyze::function_summary::{collect_param_names, FunctionSummary};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use tree_sitter::Node;

/// What one caller passes at one argument position, joined over that caller's
/// call sites.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArgOrigin {
    /// Callees whose result reaches the argument: called inside it, or
    /// assigned to or filled into a variable it names. The text of the callee
    /// expression, as the rule's own source predicate reads it.
    pub calls: BTreeSet<String>,
    /// Identifiers the argument reads that are not the caller's parameters:
    /// locals and globals alike, since a global is decided by its writers.
    pub names: BTreeSet<String>,
    /// The caller's own parameters the argument reads, by index.
    pub forwards: BTreeSet<usize>,
    /// Some call site from this caller did not supply this position.
    pub missing: bool,
}

impl ArgOrigin {
    fn join(&mut self, other: ArgOrigin) {
        self.calls.extend(other.calls);
        self.names.extend(other.names);
        self.forwards.extend(other.forwards);
        self.missing |= other.missing;
    }
}

/// One direct call site: the calling function and an origin per argument.
pub type CallSiteOrigins = (String, Vec<ArgOrigin>);

/// For every variable in `body`, the callees that feed it: `v = f(...)` and
/// `T v = f(...)` (casts and parentheses stripped), and any identifier named
/// in a call's argument list, which the call may fill (`fscanf(..., &v)`,
/// `recv(fd, buf, ...)`). The callee is its expression text.
///
/// The one definition of "fed by a call" that both a rule's own body walk
/// and the call-site record use, so a value judged in its own function and
/// the same value handed to a parameter get the same verdict.
pub fn variable_feeders(body: &Node, source: &str) -> HashMap<String, BTreeSet<String>> {
    let mut feeds: HashMap<String, BTreeSet<String>> = HashMap::new();
    let candidates = query::find_descendants_of_kinds(
        *body,
        &[
            "assignment_expression",
            "init_declarator",
            "call_expression",
        ],
    );
    for node in candidates {
        match node.kind() {
            "assignment_expression" => {
                if let (Some(lhs), Some(rhs)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if lhs.kind() == "identifier" {
                        if let Some(callee) = stripped_call_callee(&rhs, source) {
                            feeds
                                .entry(get_node_text(&lhs, source).trim().to_string())
                                .or_default()
                                .insert(callee);
                        }
                    }
                }
            }
            "init_declarator" => {
                if let (Some(decl), Some(value)) = (
                    node.child_by_field_name("declarator"),
                    node.child_by_field_name("value"),
                ) {
                    if let (Some(name), Some(callee)) = (
                        init_declarator_name(&decl, source),
                        stripped_call_callee(&value, source),
                    ) {
                        feeds.entry(name).or_default().insert(callee);
                    }
                }
            }
            "call_expression" => {
                if let (Some(f), Some(args)) = (
                    node.child_by_field_name("function"),
                    node.child_by_field_name("arguments"),
                ) {
                    let callee = get_node_text(&f, source).to_string();
                    for ident in query::find_descendants_of_kind(args, "identifier") {
                        feeds
                            .entry(get_node_text(&ident, source).trim().to_string())
                            .or_default()
                            .insert(callee.clone());
                    }
                }
            }
            _ => {}
        }
    }
    feeds
}

/// The callee text of `expr` when it is a call once casts and parentheses
/// are stripped.
fn stripped_call_callee(expr: &Node, source: &str) -> Option<String> {
    let mut node = *expr;
    loop {
        match node.kind() {
            "parenthesized_expression" => node = node.named_child(0)?,
            "cast_expression" => node = node.child_by_field_name("value")?,
            "call_expression" => {
                return node
                    .child_by_field_name("function")
                    .map(|f| get_node_text(&f, source).to_string());
            }
            _ => return None,
        }
    }
}

/// The bare identifier inside a (possibly pointer- or array-wrapped)
/// declarator.
pub fn init_declarator_name(decl: &Node, source: &str) -> Option<String> {
    let mut current = *decl;
    loop {
        if current.kind() == "identifier" || current.kind() == "field_identifier" {
            return Some(get_node_text(&current, source).trim().to_string());
        }
        current = current.child_by_field_name("declarator")?;
    }
}

/// The origin of one argument expression, read the way the rule's own
/// operand walk reads it: through parentheses, casts, binary and unary
/// operators; a call contributes its callee, an identifier its feeders and
/// its name, or its index when it is one of the caller's parameters. Anything
/// else (a literal, a field or subscript read) contributes nothing.
fn origin_of(
    arg: &Node,
    source: &str,
    params: &[String],
    feeds: &HashMap<String, BTreeSet<String>>,
    out: &mut ArgOrigin,
) {
    match arg.kind() {
        "call_expression" => {
            if let Some(f) = arg.child_by_field_name("function") {
                out.calls.insert(get_node_text(&f, source).to_string());
            }
        }
        "identifier" => {
            let name = get_node_text(arg, source).trim().to_string();
            if let Some(callees) = feeds.get(&name) {
                out.calls.extend(callees.iter().cloned());
            }
            match params.iter().position(|p| *p == name) {
                Some(idx) => {
                    out.forwards.insert(idx);
                }
                None => {
                    out.names.insert(name);
                }
            }
        }
        "parenthesized_expression" => {
            if let Some(inner) = arg.named_child(0) {
                origin_of(&inner, source, params, feeds, out);
            }
        }
        "cast_expression" => {
            if let Some(value) = arg.child_by_field_name("value") {
                origin_of(&value, source, params, feeds, out);
            }
        }
        "binary_expression" => {
            for field in ["left", "right"] {
                if let Some(side) = arg.child_by_field_name(field) {
                    origin_of(&side, source, params, feeds, out);
                }
            }
        }
        "unary_expression" | "update_expression" => {
            if let Some(inner) = arg.child_by_field_name("argument") {
                origin_of(&inner, source, params, feeds, out);
            }
        }
        _ => {}
    }
}

/// Record every direct call site in the translation unit under `node`, keyed
/// by callee name: the calling function and each argument's origin.
pub fn collect_callsite_arg_origins_from_tree(
    node: &Node,
    source: &str,
    out: &mut HashMap<String, Vec<CallSiteOrigins>>,
) {
    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else {
            continue;
        };
        match child.kind() {
            "function_definition" => collect_in_function(&child, source, out),
            kind if crate::analyze::prescan::wraps_definitions(kind) => {
                collect_callsite_arg_origins_from_tree(&child, source, out);
            }
            _ => {}
        }
    }
}

fn collect_in_function(func: &Node, source: &str, out: &mut HashMap<String, Vec<CallSiteOrigins>>) {
    let (Some(caller), Some(body)) = (
        lang_parsing_substrate::calls::get_function_name(*func, source),
        func.child_by_field_name("body"),
    ) else {
        return;
    };
    let params = collect_param_names(func, source);
    let feeds = variable_feeders(&body, source);
    for call in query::find_descendants_of_kind(body, "call_expression") {
        let (Some(function), Some(args)) = (
            call.child_by_field_name("function"),
            call.child_by_field_name("arguments"),
        ) else {
            continue;
        };
        if function.kind() != "identifier" {
            continue;
        }
        let callee = get_node_text(&function, source).trim().to_string();
        let mut origins = Vec::new();
        let mut cursor = args.walk();
        for arg in args.named_children(&mut cursor) {
            if arg.kind() == "comment" {
                continue;
            }
            let mut origin = ArgOrigin::default();
            origin_of(&arg, source, &params, &feeds, &mut origin);
            origins.push(origin);
        }
        out.entry(callee)
            .or_default()
            .push((caller.clone(), origins));
    }
}

/// Fold the collected call sites onto each callee's summary
/// (`callsite_arg_origins`, `callsite_origin_callers`), and mark a callee
/// whose call graph names a caller no collected call site came from
/// (`callsite_origin_gap`): a call this record does not describe, so no
/// verdict may rest on it. `exact_callers` is the call graph inverted
/// without pooling same-named statics, keyed as `summaries` is.
pub fn aggregate(
    call_sites: &HashMap<String, Vec<CallSiteOrigins>>,
    exact_callers: &HashMap<String, HashSet<String>>,
    summaries: &mut HashMap<String, FunctionSummary>,
) {
    for (callee, sites) in call_sites {
        let Some(summary) = summaries.get_mut(callee) else {
            continue;
        };
        let width = sites.iter().map(|(_, a)| a.len()).max().unwrap_or(0);
        for (caller, args) in sites {
            summary.callsite_origin_callers.insert(caller.clone());
            for idx in 0..width {
                let origin = args.get(idx).cloned().unwrap_or(ArgOrigin {
                    missing: true,
                    ..Default::default()
                });
                summary
                    .callsite_arg_origins
                    .entry(idx)
                    .or_default()
                    .entry(caller.clone())
                    .or_default()
                    .join(origin);
            }
        }
    }
    for (callee, summary) in summaries.iter_mut() {
        if let Some(callers) = exact_callers.get(callee) {
            if callers
                .iter()
                .any(|c| !summary.callsite_origin_callers.contains(c))
            {
                summary.callsite_origin_gap = true;
            }
        }
    }
}

/// Whether parameter `idx` of `name` may receive a value `is_risky` rejects.
///
/// Clean only when the function's caller set is closed by linkage
/// (`FunctionSummary::caller_set_is_closed_by_linkage`), every caller the call
/// graph names has a collected call site, there is at least one, every one of
/// them supplies the position, and `is_risky` accepts what each passes. An
/// argument that forwards the caller's own parameter needs the same of that
/// parameter in turn, up the chain. Anything the record cannot answer is
/// risky.
///
/// The closed-by-linkage gate, not the declaration-aware one: an argument
/// that is merely not from a source is the rule's reporting scope, not a
/// proof about the value, so a declared closed program does not widen it.
pub fn param_is_risky(
    name: &str,
    idx: usize,
    summaries: &(impl SummaryLookup + ?Sized),
    is_risky: impl Fn(&ArgOrigin) -> bool,
) -> bool {
    let mut stack = vec![(name.to_string(), idx)];
    let mut visited: HashSet<(String, usize)> = HashSet::new();
    while let Some((func, i)) = stack.pop() {
        if !visited.insert((func.clone(), i)) {
            continue;
        }
        let Some(summary) = summaries.get(&func) else {
            return true;
        };
        if !summary.caller_set_is_closed_by_linkage()
            || summary.callsite_origin_gap
            || summary.callsite_origin_callers.is_empty()
        {
            return true;
        }
        let Some(per_caller) = summary.callsite_arg_origins.get(&i) else {
            return true;
        };
        for caller in &summary.callsite_origin_callers {
            let Some(origin) = per_caller.get(caller) else {
                return true;
            };
            if origin.missing || is_risky(origin) {
                return true;
            }
            stack.extend(origin.forwards.iter().map(|j| (caller.clone(), *j)));
        }
    }
    false
}

/// `callsite_arg_origins`' value type: per caller key, the joined origin.
pub type OriginsByCaller = BTreeMap<String, ArgOrigin>;

#[cfg(test)]
mod tests {
    use super::*;

    fn origins_of(code: &str) -> HashMap<String, Vec<CallSiteOrigins>> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let mut out = HashMap::new();
        collect_callsite_arg_origins_from_tree(&tree.root_node(), code, &mut out);
        out
    }

    fn closed() -> FunctionSummary {
        FunctionSummary {
            has_internal_linkage: true,
            ..Default::default()
        }
    }

    #[test]
    fn an_argument_records_its_feeding_callees_names_and_forwarded_parameters() {
        let sites = origins_of(
            "void caller(int p) { int a = rand(); int b; fscanf(f, \"%d\", &b); \
             sink(a, (long)(b + p), 3, g); }",
        );
        let (caller, args) = &sites["sink"][0];
        assert_eq!(caller, "caller");
        assert!(args[0].calls.contains("rand"));
        assert!(args[1].calls.contains("fscanf"));
        assert!(args[1].forwards.contains(&0));
        assert!(
            !args[1].names.contains("p"),
            "a parameter is a forward, not a name"
        );
        assert_eq!(
            args[2],
            ArgOrigin::default(),
            "a literal contributes nothing"
        );
        assert!(args[3].names.contains("g"));
    }

    #[test]
    fn a_caller_the_call_graph_names_but_no_collected_site_came_from_is_a_gap() {
        let sites = HashMap::from([(
            "sink".to_string(),
            vec![("direct".to_string(), vec![ArgOrigin::default()])],
        )]);
        let mut summaries = HashMap::from([("sink".to_string(), closed())]);
        let exact = HashMap::from([(
            "sink".to_string(),
            HashSet::from(["direct".to_string(), "via_pointer".to_string()]),
        )]);
        aggregate(&sites, &exact, &mut summaries);
        assert!(summaries["sink"].callsite_origin_gap);
        assert!(param_is_risky("sink", 0, &summaries, |_| false));
    }

    #[test]
    fn a_forwarded_parameter_is_judged_by_its_own_callers_and_a_short_call_is_missing() {
        let mut summaries = HashMap::from([
            ("sink".to_string(), closed()),
            ("relay".to_string(), closed()),
        ]);
        let forward = ArgOrigin {
            forwards: BTreeSet::from([0]),
            ..Default::default()
        };
        let risky = ArgOrigin {
            calls: BTreeSet::from(["rand".to_string()]),
            ..Default::default()
        };
        let sites = HashMap::from([
            (
                "sink".to_string(),
                vec![("relay".to_string(), vec![forward])],
            ),
            (
                "relay".to_string(),
                vec![
                    ("top".to_string(), vec![risky]),
                    ("short".to_string(), vec![]),
                ],
            ),
        ]);
        aggregate(&sites, &HashMap::new(), &mut summaries);
        assert!(summaries["relay"].callsite_arg_origins[&0]["short"].missing);
        let by_rand = |o: &ArgOrigin| o.calls.contains("rand");
        assert!(param_is_risky("sink", 0, &summaries, by_rand));
        // Without the short call and with a clean top caller, it is clean.
        let mut summaries = HashMap::from([
            ("sink".to_string(), closed()),
            ("relay".to_string(), closed()),
        ]);
        let sites = HashMap::from([
            (
                "sink".to_string(),
                vec![(
                    "relay".to_string(),
                    vec![ArgOrigin {
                        forwards: BTreeSet::from([0]),
                        ..Default::default()
                    }],
                )],
            ),
            (
                "relay".to_string(),
                vec![("top".to_string(), vec![ArgOrigin::default()])],
            ),
        ]);
        aggregate(&sites, &HashMap::new(), &mut summaries);
        assert!(!param_is_risky("sink", 0, &summaries, by_rand));
    }

    #[test]
    fn an_exported_function_or_one_without_callers_is_risky() {
        let mut open = closed();
        open.has_internal_linkage = false;
        let summaries = HashMap::from([
            ("exported".to_string(), open),
            ("uncalled".to_string(), closed()),
        ]);
        assert!(param_is_risky("exported", 0, &summaries, |_| false));
        assert!(param_is_risky("uncalled", 0, &summaries, |_| false));
    }
}
