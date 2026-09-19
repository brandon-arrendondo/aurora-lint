// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Print the ownership-relevant fields of named function summaries from a
//! saved prescan cache, so a "why does MEM31-C think this callee frees /
//! allocates / stores?" question is answered by reading the summary the
//! rule actually saw rather than by guessing from source.
//!
//! ```text
//! aurora-lint <scan> ... --save-prescan /tmp/ctx.json
//! cargo run --release --example dump_summary -- /tmp/ctx.json decrRefCount zfree
//! ```
//!
//! This is how task 1227 found that valkey's `#define zfree valkey_free`
//! sent the transitive-frees edge to a name with no summary.

use aurora_lint::analyze::context::ProjectContext;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: dump_summary <prescan-cache> <function-name>...");
        std::process::exit(2);
    }
    let ctx = match ProjectContext::load_from_file(std::path::Path::new(&args[1])) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("cannot load {}: {e}", args[1]);
            std::process::exit(1);
        }
    };
    for name in &args[2..] {
        match ctx.function_summaries.get(name) {
            Some(s) => println!(
                "{name}:\n  returns_allocation={} returns_pointer={} returned_callees={:?}\n  returned_value_escapes={} returned_value_passthroughs={:?}\n  frees_params={:?} frees_params_guessed={:?} frees_param_pointees={:?} frees_param_fields={:?}\n  stores_params={:?} param_passthroughs={:?}",
                s.returns_allocation,
                s.returns_pointer,
                s.returned_callees,
                s.returned_value_escapes,
                s.returned_value_passthroughs,
                s.frees_params,
                s.frees_params_guessed,
                s.frees_param_pointees,
                s.frees_param_fields,
                s.stores_params,
                s.param_passthroughs
            ),
            None => println!("{name}: no summary"),
        }
    }
}
