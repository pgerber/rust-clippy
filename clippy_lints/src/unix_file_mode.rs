use rustc::hir::{intravisit, ExprCall, ExprLit, ExprPath};
use rustc::hir::def::Def;
use rustc::hir;
use rustc::lint::*;
use syntax::ast::*;
use syntax::ast;
use syntax::codemap::Span;
use syntax::visit::FnKind;
use utils::{constants, get_trait_def_id, match_def_path, match_trait_method, paths, span_lint, span_help_and_lint,
            snippet, snippet_opt, span_lint_and_then};
use rustc::hir::ExprMethodCall;
use syntax::codemap::Spanned;
use utils::match_type;
use rustc::ty;
use utils::implements_trait;

declare_lint! {
    pub INVALID_FILE_MODE,
    Deny,
    "invalid file mode"
}

declare_lint! {
    pub NON_OCTAL_FILE_MODE,
    Warn,
    "file mode is a non-octal literal"
}

declare_lint! {
    pub WORLD_WRITEABLE_FILE_MODE,
    Warn,
    "file mode allows writing for anyone"
}

declare_lint! {
    pub WORLD_READABLE_FILE_MODE,
    Allow,
    "file mode allows writing for anyone"
}

#[derive(Copy, Clone)]
pub struct UnixFileMode;

impl LintPass for UnixFileMode {
    fn get_lints(&self) -> LintArray {
        lint_array!(INVALID_FILE_MODE, NON_OCTAL_FILE_MODE, WORLD_READABLE_FILE_MODE, WORLD_WRITEABLE_FILE_MODE)
    }
}

impl<'a, 'tcx> LateLintPass<'a, 'tcx> for UnixFileMode {
    fn check_expr(&mut self, cx: &LateContext<'a, 'tcx>, expr: &'tcx ::rustc::hir::Expr) {
        if_let_chain! {[
            let hir::ExprMethodCall(name, ref x, ref args) = expr.node,
            &*name.node.as_str() == "mode",
            args.len() == 2,
        ], {
            if match_trait_method(cx, expr, &["std", "sys", "imp", "ext", "fs", "DirBuilderExt"])
                    || match_trait_method(cx, expr, &["std", "sys", "imp", "ext", "fs", "OpenOptionsExt"]) {
                check_file_mode(cx, &args[1]);
            }
        }}
    }
}

fn check_file_mode(cx: &LateContext, expr: &::rustc::hir::Expr) {
    if_let_chain! {[
        let ExprLit(ref lit) = expr.node
        let LitKind::Int(value, ..) = lit
    ] , {
        if value > 0o7777 => {
            span_help_and_lint(cx,
                               INVALID_FILE_MODE,
                               expr.span,
                               "file mode invalid",
                               "consider using …");
        }
        if value & 0o002 != 0 => {
            span_help_and_lint(cx,
                               WORLD_WRITEABLE_FILE_MODE,
                               expr.span,
                               "world-writeable unix permissinos",
                               "consider using …");
        }
        if value & 0o004 != 0 => {
            span_help_and_lint(cx,
                               WORLD_READABLE_FILE_MODE,
                               expr.span,
                               "world-readable unix permissinos",
                               "consider using …");
        }
    }}
}
