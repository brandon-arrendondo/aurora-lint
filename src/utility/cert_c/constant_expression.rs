// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Whether an expression is an integer constant expression (C11 6.6), read
//! from what its names resolve to, never from how they are spelled.
//!
//! An integer constant expression is built from integer and character
//! constants, enumerators, `sizeof` and `_Alignof` of a type that is not
//! variably modified, casts, and operators over those. A name bound to an
//! object is not one, `const` or not: `const int k = 4; int a[k];` declares
//! a variable-length array. A macro is read through its replacement list,
//! which is tested the same way where the macro is used, so
//! `#define TOP ((unsigned long)ki_end)` is not a constant and
//! `#define N (2 * slots)` is one when `slots` is an enumerator there.
//!
//! The answer has three values. A name that nothing in reach declares or
//! defines (a header the scan did not read, say) is [`Constness::Unknown`],
//! and each caller says which way that falls for it.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use lang_parsing_substrate::query;
use tree_sitter::{Node, Tree};

use crate::analyze::check_macros::{collect_macro_definitions, MacroDefinition};
use crate::analyze::context::ProjectContext;
use crate::utility::cert_c::ast_utils::{
    enumerator_in_scope, get_node_text, resolve_identifier_declarator, typedef_definition_in_scope,
};
use crate::utility::cert_c::declarator_utils::{
    inner_declarator, typedef_declarators, TypedefShape,
};
use crate::utility::cert_c::expr_type::is_standard_typedef_name;

/// Whether an expression is an integer constant expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Constness {
    /// It is one in every build that defines the names it uses.
    Constant,
    /// It is not: it reads an object, calls a function, or takes the size
    /// of a variably modified type. Also the answer past the work budget.
    NotConstant,
    /// It uses a name nothing in reach declares or defines, or a macro whose
    /// replacement list does not read as an expression.
    Unknown,
}

impl Constness {
    /// Both parts together: not constant if either is not, else unknown if
    /// either is.
    fn and(self, other: Self) -> Self {
        use Constness::*;
        match (self, other) {
            (NotConstant, _) | (_, NotConstant) => NotConstant,
            (Unknown, _) | (_, Unknown) => Unknown,
            _ => Constant,
        }
    }

    fn from_bool(constant: bool) -> Self {
        if constant {
            Constness::Constant
        } else {
            Constness::NotConstant
        }
    }
}

/// The project's tables the test reads: macro definitions, and the typedefs
/// the scanned headers declare.
#[derive(Default, Clone)]
pub struct ProjectTables {
    definitions: Arc<HashMap<String, Vec<MacroDefinition>>>,
    typedefs: Arc<HashMap<String, String>>,
    struct_aliases: Arc<HashMap<String, String>>,
    structs: Arc<HashMap<String, HashMap<String, String>>>,
    /// Every function the scanned files define, and every one a scanned
    /// header declares: a name some build calls as a function.
    functions: Arc<std::collections::HashSet<String>>,
    header_functions: Arc<std::collections::HashSet<String>>,
}

impl ProjectTables {
    /// The tables `context` holds.
    pub fn from_context(context: &ProjectContext) -> Self {
        Self {
            definitions: context.macro_definitions.clone(),
            typedefs: context.typedef_types.clone(),
            struct_aliases: context.struct_typedef_aliases.clone(),
            structs: context.struct_field_types.clone(),
            functions: Arc::new(context.call_graph.keys().cloned().collect()),
            header_functions: context.header_declared_functions.clone(),
        }
    }
}

/// The most steps one expression may take to be shown constant. A size whose
/// `sizeof` operands name arrays sized the same way is re-read once per
/// reference, which doubles per level when each level names two; past the
/// budget the expression is not shown constant.
const WORK: usize = 4096;

/// How deep the test follows operands, typedefs and macros.
const DEPTH: usize = 64;

/// What one file defines, read only when an expression needs it.
struct FileTables {
    /// The file's macro definitions, in its live `#if` arms.
    definitions: HashMap<String, Vec<MacroDefinition>>,
    /// Each name a typedef in the file defines, and whether one is in a
    /// block. Only a block can declare a variably modified type, so only
    /// those names need the scoped lookup, whose cost grows with the file.
    typedefs: HashMap<String, bool>,
}

/// A macro's replacement list, parsed as the initializer of a declaration.
struct MacroBody {
    text: String,
    tree: Tree,
}

/// The test for the expressions of one file.
pub struct ConstantExpressions<'a, 'p> {
    root: Node<'a>,
    source: &'a str,
    project: &'p ProjectTables,
    file: OnceCell<FileTables>,
    /// Each replacement list read so far, by its text; `None` when it does
    /// not parse as an expression.
    bodies: RefCell<HashMap<String, Option<Rc<MacroBody>>>>,
    /// The macros being read, innermost last: one is not expanded inside its
    /// own replacement list (C11 6.10.3.4p2).
    expanding: RefCell<Vec<String>>,
    work_left: Cell<usize>,
    /// Whether a read since this was cleared stopped at the depth cap or
    /// the budget, so its answer means "not shown", and is not kept.
    cut_short: Cell<bool>,
    /// Whether the object a declarator (by start byte) declares has a
    /// constant size. A chain of arrays each sized by `sizeof` of the one
    /// before reads each link once.
    fixed_size_objects: RefCell<HashMap<usize, Constness>>,
    /// The same for a typedef, by its definition's start byte and the name
    /// it defines.
    fixed_size_typedefs: RefCell<HashMap<(usize, String), Constness>>,
    /// Whether the file passes a name to a call or macro, by name.
    handed: RefCell<HashMap<String, bool>>,
}

impl<'a, 'p> ConstantExpressions<'a, 'p> {
    /// The test for the file whose tree is `root`.
    pub fn new(root: Node<'a>, source: &'a str, project: &'p ProjectTables) -> Self {
        Self {
            root,
            source,
            project,
            file: OnceCell::new(),
            bodies: RefCell::new(HashMap::new()),
            expanding: RefCell::new(Vec::new()),
            work_left: Cell::new(WORK),
            cut_short: Cell::new(false),
            fixed_size_objects: RefCell::new(HashMap::new()),
            fixed_size_typedefs: RefCell::new(HashMap::new()),
            handed: RefCell::new(HashMap::new()),
        }
    }

    /// Whether `expr`, a node of this file, is an integer constant
    /// expression where it stands.
    pub fn integer_constant_expression(&self, expr: &Node<'a>) -> Constness {
        self.work_left.set(WORK);
        self.cut_short.set(false);
        self.expression(*expr, self.source, *expr, 0)
    }

    /// Whether `expr`, read in `src`, is an integer constant expression,
    /// resolving its names where `anchor`, a node of this file, stands: the
    /// expression itself, or the use of the macro whose replacement list it
    /// is part of.
    fn expression<'e>(
        &self,
        expr: Node<'e>,
        src: &str,
        anchor: Node<'a>,
        depth: usize,
    ) -> Constness {
        if depth > DEPTH || self.work_left.get() == 0 {
            self.cut_short.set(true);
            return Constness::NotConstant;
        }
        self.work_left.set(self.work_left.get() - 1);
        let operand = |child: Node<'e>| self.expression(child, src, anchor, depth + 1);
        match expr.kind() {
            "number_literal" => Constness::from_bool(is_integer_literal(get_node_text(&expr, src))),
            "char_literal" => Constness::Constant,
            // Only the operand's type matters, and it is constant unless the
            // type is variably modified (C11 6.5.3.4p2).
            "sizeof_expression" | "alignof_expression" => match expr.child_by_field_name("value") {
                Some(value) => self.sizeof_operand(value, src, anchor, depth),
                None => expr
                    .child_by_field_name("type")
                    .map_or(Constness::NotConstant, |ty| {
                        self.fixed_size_type(ty, src, anchor, depth)
                    }),
            },
            "parenthesized_expression" => {
                expr.named_child(0).map_or(Constness::NotConstant, operand)
            }
            // A floating constant may be the immediate operand of a cast
            // (C11 6.6p6).
            "cast_expression" => match expr.child_by_field_name("value") {
                Some(value) if value.kind() == "number_literal" => Constness::Constant,
                Some(value) => operand(value),
                None => Constness::NotConstant,
            },
            "unary_expression" => {
                let operator = expr
                    .child_by_field_name("operator")
                    .map(|op| get_node_text(&op, src))
                    .unwrap_or("");
                if !matches!(operator, "-" | "+" | "~" | "!") {
                    return Constness::NotConstant;
                }
                expr.child_by_field_name("argument")
                    .map_or(Constness::NotConstant, operand)
            }
            "binary_expression" => match (
                expr.child_by_field_name("left"),
                expr.child_by_field_name("right"),
            ) {
                (Some(left), Some(right)) => operand(left).and(operand(right)),
                _ => Constness::NotConstant,
            },
            "conditional_expression" => ["condition", "consequence", "alternative"]
                .iter()
                .map(|field| {
                    expr.child_by_field_name(field)
                        .map_or(Constness::NotConstant, operand)
                })
                .fold(Constness::Constant, Constness::and),
            "identifier" => self.name(get_node_text(&expr, src), anchor, depth),
            "call_expression" => self.macro_call(expr, src, anchor, depth),
            // `offsetof(type, member)` is an integer constant expression
            // (C11 7.19p3) for a type of constant size.
            "offsetof_expression" => expr
                .child_by_field_name("type")
                .map_or(Constness::NotConstant, |ty| {
                    self.fixed_size_type(ty, src, anchor, depth)
                }),
            _ => Constness::NotConstant,
        }
    }

    /// What the name `name` stands for where `anchor` is: an object is not a
    /// constant, an enumerator is, and a macro is what its replacement list
    /// is.
    fn name(&self, name: &str, anchor: Node<'a>, depth: usize) -> Constness {
        if resolve_identifier_declarator(&anchor, name, self.source).is_some() {
            return Constness::NotConstant;
        }
        if enumerator_in_scope(&anchor, name, self.source) {
            return Constness::Constant;
        }
        self.macro_constness(name, anchor, depth)
            .unwrap_or(Constness::Unknown)
    }

    /// What the object-like macro `name` expands to where `anchor` is, over
    /// every live definition: the file's own when it has one, else the
    /// project's. `None` when neither defines it as an object-like macro,
    /// or it is being expanded already.
    fn macro_constness(&self, name: &str, anchor: Node<'a>, depth: usize) -> Option<Constness> {
        if self.expanding.borrow().iter().any(|n| n == name) {
            return None;
        }
        let file = self.file();
        let definitions = file
            .definitions
            .get(name)
            .filter(|defs| !defs.is_empty())
            .or_else(|| self.project.definitions.get(name))?;
        let mut objects = definitions
            .iter()
            .filter(|def| !matches!(def, MacroDefinition::Function { .. }))
            .peekable();
        objects.peek()?;
        let bodies: Vec<Option<String>> = objects
            .map(|def| match def {
                MacroDefinition::Object { body } => Some(body.clone()),
                _ => None,
            })
            .collect();
        self.expanding.borrow_mut().push(name.to_string());
        let constness = bodies
            .iter()
            .map(|body| match body {
                Some(body) => self.replacement_list(body, anchor, depth + 1),
                None => Constness::Unknown,
            })
            .fold(Constness::Constant, Constness::and);
        self.expanding.borrow_mut().pop();
        Some(constness)
    }

    /// A call, which is a constant only when its callee is a function-like
    /// macro: the replacement list, with each parameter replaced by its
    /// argument, is tested where the call is, over every live definition
    /// (the file's own when it has one, else the project's). A call of a
    /// function, or of a name no definition makes a function-like macro,
    /// is not a constant.
    fn macro_call<'e>(
        &self,
        call: Node<'e>,
        src: &str,
        anchor: Node<'a>,
        depth: usize,
    ) -> Constness {
        let (Some(callee), Some(arguments)) = (
            call.child_by_field_name("function"),
            call.child_by_field_name("arguments"),
        ) else {
            return Constness::NotConstant;
        };
        if callee.kind() != "identifier" {
            return Constness::NotConstant;
        }
        let name = get_node_text(&callee, src);
        // A name some build declares as a function is a call there, whatever
        // a macro makes it in another (`sqlite3SchemaMutexHeld` is `1` only
        // where mutexes are compiled out).
        let function =
            self.project.functions.contains(name) || self.project.header_functions.contains(name);
        if function
            || self.expanding.borrow().iter().any(|n| n == name)
            || resolve_identifier_declarator(&anchor, name, self.source).is_some()
        {
            return Constness::NotConstant;
        }
        let mut cursor = arguments.walk();
        let args: Vec<&str> = arguments
            .named_children(&mut cursor)
            .filter(|n| n.kind() != "comment")
            .map(|n| get_node_text(&n, src))
            .collect();
        let file = self.file();
        let Some(definitions) = file
            .definitions
            .get(name)
            .filter(|defs| !defs.is_empty())
            .or_else(|| self.project.definitions.get(name))
        else {
            // A name nothing in reach defines may be a header's macro
            // (`offsetof` from `<stddef.h>`).
            return Constness::Unknown;
        };
        let expansions: Vec<Option<String>> = definitions
            .iter()
            .map(|def| match def {
                MacroDefinition::Function { params, body } => substitute(params, body, &args),
                _ => None,
            })
            .collect();
        if expansions.is_empty() {
            return Constness::NotConstant;
        }
        self.expanding.borrow_mut().push(name.to_string());
        let constness = expansions
            .iter()
            .map(|expansion| match expansion {
                Some(text) => self.replacement_list(text, anchor, depth + 1),
                None => Constness::Unknown,
            })
            .fold(Constness::Constant, Constness::and);
        self.expanding.borrow_mut().pop();
        constness
    }

    /// Whether the replacement list `body` is an integer constant expression
    /// where `anchor` is.
    fn replacement_list(&self, body: &str, anchor: Node<'a>, depth: usize) -> Constness {
        let Some(parsed) = self.parsed_body(body) else {
            return Constness::Unknown;
        };
        let init = query::find_descendants_of_kind(parsed.tree.root_node(), "init_declarator")
            .into_iter()
            .next()
            .and_then(|d| d.child_by_field_name("value"));
        match init {
            Some(value) => self.expression(value, &parsed.text, anchor, depth),
            None => Constness::Unknown,
        }
    }

    fn parsed_body(&self, body: &str) -> Option<Rc<MacroBody>> {
        if let Some(known) = self.bodies.borrow().get(body) {
            return known.clone();
        }
        let parsed = parse_replacement_list(body).map(Rc::new);
        self.bodies
            .borrow_mut()
            .insert(body.to_string(), parsed.clone());
        parsed
    }

    /// A `sizeof` or `_Alignof` operand that is an expression. A string
    /// literal has a fixed array type, and a struct member is never variably
    /// modified (C11 6.7.2.1); `sizeof(T)` for a typedef `T` in scope parses
    /// as a name in parentheses; a name of an object is constant when the
    /// object is declared fixed-size. Any other operand, `*p` or `m[0]`, is
    /// not shown to be.
    fn sizeof_operand<'e>(
        &self,
        value: Node<'e>,
        src: &str,
        anchor: Node<'a>,
        depth: usize,
    ) -> Constness {
        let mut inner = value;
        while inner.kind() == "parenthesized_expression" {
            match inner.named_child(0) {
                Some(n) => inner = n,
                None => break,
            }
        }
        match inner.kind() {
            "string_literal" | "concatenated_string" | "field_expression" => Constness::Constant,
            "identifier" => {
                let name = get_node_text(&inner, src);
                match self.block_typedef_in_scope(anchor, name) {
                    Some(definition) => self.fixed_size_typedef(definition, name, depth),
                    None if self.names_header_type(anchor, name) => Constness::Constant,
                    None if is_standard_typedef_name(name)
                        && resolve_identifier_declarator(&anchor, name, self.source).is_none() =>
                    {
                        Constness::Constant
                    }
                    None if resolve_identifier_declarator(&anchor, name, self.source).is_some() => {
                        self.names_fixed_size_object(anchor, name, depth)
                    }
                    None => self.sizeof_unresolved_name(name, anchor, depth),
                }
            }
            _ => Constness::NotConstant,
        }
    }

    /// `sizeof` of a name nothing in this file declares. An object-like
    /// macro is what `sizeof` of its replacement list is
    /// (`sizeof(PREFIX)` for `#define PREFIX ""`). Otherwise the name is a
    /// header's type or object, neither of which can be variably modified,
    /// since that takes a declaration in a block of this file, unless the
    /// file hands the name to a macro, which may declare it so
    /// (`VBUF(buf_t, n);`); either way the file does not show which, so it
    /// is unknown, or not shown constant where a macro may declare it.
    fn sizeof_unresolved_name(&self, name: &str, anchor: Node<'a>, depth: usize) -> Constness {
        let objects: Vec<String> = {
            let file = self.file();
            file.definitions
                .get(name)
                .filter(|defs| !defs.is_empty())
                .or_else(|| self.project.definitions.get(name))
                .map(|defs| {
                    defs.iter()
                        .filter_map(|def| match def {
                            MacroDefinition::Object { body } => Some(body.clone()),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        if !objects.is_empty() && !self.expanding.borrow().iter().any(|n| n == name) {
            self.expanding.borrow_mut().push(name.to_string());
            let constness = objects
                .iter()
                .map(|body| self.replacement_list(&format!("sizeof({body})"), anchor, depth + 1))
                .fold(Constness::Constant, Constness::and);
            self.expanding.borrow_mut().pop();
            return constness;
        }
        if self.handed_to_a_macro(name) {
            Constness::NotConstant
        } else {
            Constness::Unknown
        }
    }

    /// Whether some definition of the function-like macro `name` (the
    /// file's own, else the project's) declares its parameter at `index`:
    /// `#define VBUF(name, len) char name[len]` declares its first. A macro
    /// that only reads it (`memcpy(D, S, N)` wrapped for debugging) does not.
    fn declares_its_argument(&self, name: &str, index: usize) -> bool {
        let file = self.file();
        let Some(definitions) = file
            .definitions
            .get(name)
            .filter(|defs| !defs.is_empty())
            .or_else(|| self.project.definitions.get(name))
        else {
            return false;
        };
        definitions.iter().any(|def| {
            let MacroDefinition::Function { params, body } = def else {
                return false;
            };
            let Some(param) = params.get(index) else {
                return false;
            };
            let text = format!("void aurora_lint_macro_body(void) {{\n{body};\n}}\n");
            let mut parser = tree_sitter::Parser::new();
            if parser.set_language(&crate::parser::c_language()).is_err() {
                return false;
            }
            let Some(tree) = parser.parse(&text, None) else {
                return false;
            };
            query::find_descendants_of_kind(tree.root_node(), "declaration")
                .into_iter()
                .any(|declaration| {
                    let mut cursor = declaration.walk();
                    let declared = declaration
                        .children_by_field_name("declarator", &mut cursor)
                        .any(|d| {
                            std::iter::successors(Some(d), inner_declarator).any(|n| {
                                n.kind() == "identifier" && get_node_text(&n, &text) == param
                            })
                        });
                    declared
                })
        })
    }

    /// Whether this file passes `name` to a function-like macro invoked as a
    /// statement (`VBUF(buf_t, n);`), the shape of a macro that declares
    /// something. A function such as `memcpy` declares nothing.
    fn handed_to_a_macro(&self, name: &str) -> bool {
        if let Some(&known) = self.handed.borrow().get(name) {
            return known;
        }
        let found = query::find_descendants_of_kind(self.root, "argument_list")
            .into_iter()
            .filter(|args| {
                args.parent().is_some_and(|call| {
                    call.kind() == "call_expression"
                        && call
                            .parent()
                            .is_some_and(|p| p.kind() == "expression_statement")
                })
            })
            .any(|args| {
                let Some(callee) = args
                    .parent()
                    .and_then(|call| call.child_by_field_name("function"))
                else {
                    return false;
                };
                let callee = get_node_text(&callee, self.source);
                let mut cursor = args.walk();
                let positions: Vec<usize> = args
                    .named_children(&mut cursor)
                    .filter(|n| n.kind() != "comment")
                    .enumerate()
                    .filter(|(_, a)| {
                        a.kind() == "identifier" && get_node_text(a, self.source) == name
                    })
                    .map(|(i, _)| i)
                    .collect();
                positions
                    .into_iter()
                    .any(|i| self.declares_its_argument(callee, i))
            });
        self.handed.borrow_mut().insert(name.to_string(), found);
        found
    }

    /// Whether `name` resolves, where `anchor` is, to an object whose
    /// `sizeof` is constant: every array size in its declarator is constant
    /// (`int a[]` takes its size from the initializer), and so is the type it
    /// is declared with. A name that resolves to no declaration is not shown
    /// to be one: a macro can declare a variable-length array the file's
    /// declarations do not show (ADR-0006).
    fn names_fixed_size_object(&self, anchor: Node<'a>, name: &str, depth: usize) -> Constness {
        let Some((declaration, declarator)) =
            resolve_identifier_declarator(&anchor, name, self.source)
        else {
            return Constness::NotConstant;
        };
        if let Some(&known) = self
            .fixed_size_objects
            .borrow()
            .get(&declarator.start_byte())
        {
            return known;
        }
        let outer_cut = self.cut_short.replace(false);
        let fixed = self
            .array_sizes_constant(declarator, self.source, declarator, depth)
            .and(
                declaration
                    .child_by_field_name("type")
                    .map_or(Constness::Constant, |ty| {
                        self.fixed_size_specifier(ty, self.source, declarator, depth)
                    }),
            );
        if self.cut_short.get() {
            self.cut_short.set(true);
        } else {
            self.fixed_size_objects
                .borrow_mut()
                .insert(declarator.start_byte(), fixed);
            self.cut_short.set(outer_cut);
        }
        fixed
    }

    /// Whether `name`, a `sizeof` operand, names a typedef at file scope, in
    /// this file or a scanned header: it resolves to nothing here, no macro
    /// in reach defines it, and a file-scope typedef of this file or the
    /// project's typedef tables name it a type. A typedef at file scope
    /// cannot be variably modified, so its size is constant. A name no table
    /// holds is not shown to be one, whatever it is spelled like.
    fn names_header_type(&self, anchor: Node<'a>, name: &str) -> bool {
        let file = self.file();
        (file.typedefs.get(name) == Some(&false)
            || self.project.typedefs.contains_key(name)
            || self.project.struct_aliases.contains_key(name)
            || self.project.structs.contains_key(name))
            && resolve_identifier_declarator(&anchor, name, self.source).is_none()
            && !file.definitions.contains_key(name)
            && !self.project.definitions.contains_key(name)
    }

    /// Whether a `sizeof` type operand, a `type_descriptor`, names a type of
    /// constant size: its abstract declarator's array sizes and its
    /// specifier both are. tree-sitter reads `sizeof(x)` as a type when it
    /// cannot tell, so a lone name that resolves to an object is read as
    /// that object.
    fn fixed_size_type<'e>(
        &self,
        descriptor: Node<'e>,
        src: &str,
        anchor: Node<'a>,
        depth: usize,
    ) -> Constness {
        let specifier = descriptor.child_by_field_name("type");
        let declarator = descriptor.child_by_field_name("declarator");
        if let (Some(ty), None) = (specifier, declarator) {
            if ty.kind() == "type_identifier" {
                let name = get_node_text(&ty, src);
                if self.block_typedef_in_scope(anchor, name).is_none()
                    && resolve_identifier_declarator(&anchor, name, self.source).is_some()
                {
                    return self.names_fixed_size_object(anchor, name, depth);
                }
            }
        }
        declarator
            .map_or(Constness::Constant, |d| {
                self.array_sizes_constant(d, src, anchor, depth)
            })
            .and(specifier.map_or(Constness::Constant, |ty| {
                self.fixed_size_specifier(ty, src, anchor, depth)
            }))
    }

    /// Whether a type specifier has a constant size. Only a typedef in a
    /// block of this file can name a variably modified type: it is constant
    /// when the declarator that defines the name, and the type it is defined
    /// from, are. A typedef from a header, a builtin or a tag is.
    fn fixed_size_specifier<'e>(
        &self,
        specifier: Node<'e>,
        src: &str,
        anchor: Node<'a>,
        depth: usize,
    ) -> Constness {
        if depth > DEPTH {
            self.cut_short.set(true);
            return Constness::NotConstant;
        }
        if specifier.kind() != "type_identifier" {
            return Constness::Constant;
        }
        let name = get_node_text(&specifier, src);
        self.block_typedef_in_scope(anchor, name)
            .map_or(Constness::Constant, |definition| {
                self.fixed_size_typedef(definition, name, depth)
            })
    }

    /// Whether the type `definition`, a `type_definition`, gives `name` has
    /// a constant size: the declarator that defines the name, and the type
    /// it is defined from.
    fn fixed_size_typedef(&self, definition: Node<'a>, name: &str, depth: usize) -> Constness {
        let key = (definition.start_byte(), name.to_string());
        if let Some(&known) = self.fixed_size_typedefs.borrow().get(&key) {
            return known;
        }
        let outer_cut = self.cut_short.replace(false);
        let fixed = typedef_declarators(&definition)
            .into_iter()
            .filter(|d| TypedefShape::of(d, self.source).name.as_deref() == Some(name))
            .map(|d| self.array_sizes_constant(d, self.source, d, depth))
            .fold(Constness::Constant, Constness::and)
            .and(
                definition
                    .child_by_field_name("type")
                    .map_or(Constness::Constant, |ty| {
                        self.fixed_size_specifier(ty, self.source, definition, depth + 1)
                    }),
            );
        if self.cut_short.get() {
            self.cut_short.set(true);
        } else {
            self.fixed_size_typedefs.borrow_mut().insert(key, fixed);
            self.cut_short.set(outer_cut);
        }
        fixed
    }

    /// Whether every array size in a declarator chain, abstract or not, is
    /// an integer constant expression. Only the chain is walked: an array
    /// inside a size (`[sizeof(int[n])]`) is the size's own to read.
    fn array_sizes_constant<'e>(
        &self,
        declarator: Node<'e>,
        src: &str,
        anchor: Node<'a>,
        depth: usize,
    ) -> Constness {
        std::iter::successors(Some(declarator), inner_declarator)
            .filter(|n| matches!(n.kind(), "array_declarator" | "abstract_array_declarator"))
            .filter_map(|array| array.child_by_field_name("size"))
            .map(|size| self.expression(size, src, anchor, depth + 1))
            .fold(Constness::Constant, Constness::and)
    }

    fn file(&self) -> &FileTables {
        self.file.get_or_init(|| {
            let mut typedefs = HashMap::new();
            for definition in query::find_descendants_of_kind(self.root, "type_definition") {
                let in_block = std::iter::successors(definition.parent(), Node::parent)
                    .any(|a| a.kind() == "compound_statement");
                for declarator in typedef_declarators(&definition) {
                    if let Some(name) = TypedefShape::of(&declarator, self.source).name {
                        *typedefs.entry(name).or_insert(false) |= in_block;
                    }
                }
            }
            FileTables {
                definitions: collect_macro_definitions(self.source),
                typedefs,
            }
        })
    }

    /// The `type_definition` that makes `name` a type where `anchor` is,
    /// when one in a block may: [`typedef_definition_in_scope`], asked only
    /// of a name some block's typedef defines.
    fn block_typedef_in_scope(&self, anchor: Node<'a>, name: &str) -> Option<Node<'a>> {
        if self.file().typedefs.get(name) == Some(&true) {
            typedef_definition_in_scope(&anchor, name, self.source)
        } else {
            None
        }
    }
}

/// Whether `node`, part of a declaration, may declare a variable-length
/// array: one in a block, never at file scope or as a struct or union member
/// (C11 6.7.2.1p9, 6.7.6.2p2), where an array size that is no integer
/// constant expression does not compile, so the size is a constant this
/// file only cannot show.
pub fn in_block_scope(node: &Node) -> bool {
    for ancestor in std::iter::successors(node.parent(), Node::parent) {
        match ancestor.kind() {
            "field_declaration" | "function_definition" | "translation_unit" => return false,
            "compound_statement" => return true,
            _ => {}
        }
    }
    false
}

/// A function-like macro's replacement list with each parameter replaced by
/// its argument, parenthesized; `None` when the arguments do not match the
/// parameters (a variadic macro, or a count that differs).
fn substitute(params: &[String], body: &str, args: &[&str]) -> Option<String> {
    if params.iter().any(|p| p.contains("...")) || params.len() != args.len() {
        return None;
    }
    let mut out = String::with_capacity(body.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        match params.iter().position(|p| p == word.as_str()) {
            Some(i) => {
                out.push('(');
                out.push_str(args[i]);
                out.push(')');
            }
            None => out.push_str(word),
        }
        word.clear();
    };
    for c in body.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    if out.contains('#') {
        return None;
    }
    Some(out)
}

/// An integer constant, not a floating one: no `.`, and no exponent (`e` in
/// decimal, `p` in hexadecimal, where `e` is a digit).
fn is_integer_literal(text: &str) -> bool {
    let hex = text.starts_with("0x") || text.starts_with("0X");
    let exponent: &[char] = if hex { &['p', 'P'] } else { &['e', 'E'] };
    !text.contains('.') && !text.contains(exponent)
}

/// A replacement list parsed as the initializer of a file-scope declaration,
/// or `None` when it does not read as one expression.
fn parse_replacement_list(body: &str) -> Option<MacroBody> {
    if body.trim().is_empty() {
        return None;
    }
    let text = format!("int aurora_lint_replacement_list = (\n{body}\n);\n");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&crate::parser::c_language()).ok()?;
    let tree = parser.parse(&text, None)?;
    if tree.root_node().has_error() {
        return None;
    }
    Some(MacroBody { text, tree })
}
