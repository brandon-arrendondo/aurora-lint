// sqc-test: prescan
/*
 * Rule: MEM31-C
 * Source: task_652
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * Same bitfield-generator value-constructor pattern as task 580/651, but the
 * name-heuristic allocation is assigned straight into a genuine global
 * variable with NO local declaration in the assigning function at all --
 * seL4's `current_lookup_fault`/`current_fault` shape (extern-declared in a
 * header, defined in one .c file, assigned via
 * `current_lookup_fault = lookup_fault_new(...)` from several other .c
 * files). collect_value_only_locals only ever scans the one function body
 * being analyzed, so it can't see a variable with no local declaration at
 * all; this needs the project-wide `ProjectContext::value_only_globals`
 * registry instead (task 652). The `// sqc-test: prescan` marker builds
 * that registry (via prescan_single_tree) before rule.check() runs, so this
 * single-file fixture can exercise it without needing the full multi-file
 * -d harness.
 */

typedef unsigned long word_t;

struct lookup_fault {
    word_t words[2];
};
typedef struct lookup_fault lookup_fault_t;

/* Declared here the way the generated bitfield header would declare it. */
lookup_fault_t lookup_fault_new(word_t type);

/* File-scope global, plain (non-pointer) type -- never declared locally in
 * any function that assigns to it below. */
lookup_fault_t current_lookup_fault;

void set_fault(word_t type)
{
    current_lookup_fault = lookup_fault_new(type);
}

void clear_fault(void)
{
    current_lookup_fault = lookup_fault_new(0);
}
