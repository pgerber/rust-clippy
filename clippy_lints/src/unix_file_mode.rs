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
    pub SETUID_FILE_MODE,
    Warn,
    "setuid or setgid bit is set, this can lead to security issues"
}

declare_lint! {
    pub WORLD_WRITABLE_FILE_MODE,
    Warn,
    "file mode allows writing for anyone"
}

declare_lint! {
    pub WORLD_READABLE_FILE_MODE,
    Allow,
    "file mode allows writing for anyone"
}

enum FileType {
    File(u32, Span),
    Dir(u32, Span),
    None
}

#[derive(Copy, Clone)]
pub struct UnixFileMode;

impl LintPass for UnixFileMode {
    fn get_lints(&self) -> LintArray {
        lint_array!(INVALID_FILE_MODE, NON_OCTAL_FILE_MODE, SETUID_FILE_MODE, WORLD_READABLE_FILE_MODE, WORLD_WRITABLE_FILE_MODE)
    }
}

impl<'a, 'tcx> LateLintPass<'a, 'tcx> for UnixFileMode {
    fn check_expr(&mut self, cx: &LateContext<'a, 'tcx>, expr: &'tcx ::rustc::hir::Expr) {
        if_let_chain! {[
            let hir::ExprMethodCall(name, ref x, ref args) = expr.node,
            &*name.node.as_str() == "mode"
        ], {
            match file_type(cx, expr, &args) {
                FileType::File(mode, span) => {
                    check_mode_validity(&cx, span, mode);
                    check_world_writable_mode(&cx, span, mode);
                    check_world_readable_mode(&cx, span, mode);
                    check_setuid(&cx, span, mode);
                },
                FileType::Dir(mode, span) => {
                    check_mode_validity(&cx, span, mode);
                    check_world_writable_mode(&cx, span, mode);
                    check_world_readable_mode(&cx, span, mode);
               },
               FileType::None => ()
            }
        }}
    }
}

fn file_type(cx: &LateContext, expr: &::rustc::hir::Expr, args: &[::rustc::hir::Expr]) -> FileType {
    if match_trait_method(cx, expr, &["std", "sys", "imp", "ext", "fs", "OpenOptionsExt"]) {
        if let Some((mode, span)) = extract_mode(&args, 1) {
            return FileType::File(mode, span);
        }
    } else if match_trait_method(cx, expr, &["std", "sys", "imp", "ext", "fs", "DirBuilderExt"]) {
        if let Some((mode, span)) = extract_mode(&args, 1) {
            return FileType::Dir(mode, span);
        }
    }
    FileType::None
}

fn extract_mode(args: &[::rustc::hir::Expr], arg_no: usize) -> Option<(u32, Span)> {
    use rustc::hir::*;

    println!("=============================");
    println!("arg: {:?}", args[arg_no]);

    if let Some(arg) = args.get(arg_no) {
        match arg.node {
            ExprLit(..) => println!("ExprLit"),
            ExprBox(..) => println!("ExprBox"),
            ExprArray(..) => println!("ExprArray"),
            ExprCall(..) => println!("ExprCall"),
            ExprMethodCall(..) => println!("ExprMethodCall"),
            ExprTup(..) => println!("ExprTup"),
            ExprBinary(..) => println!("ExprBinary"),
            ExprUnary(..) => println!("ExprUnary"),
            ExprCast(..) => println!("ExprCast"),
            ExprType(..) => println!("ExprType"),
            ExprIf(..) => println!("ExprIf"),
            ExprWhile(..) => println!("ExprWhile"),
            ExprLoop(..) => println!("ExprLoop"),
            ExprMatch(..) => println!("ExprMatch"),
            ExprClosure(..) => println!("ExprClosure"),
            ExprBlock(..) => println!("ExprBlock"),
            ExprAssign(..) => println!("ExprAssign"),
            ExprAssignOp(..) => println!("ExprAssignOp"),
            ExprField(..) => println!("ExprField"),
            ExprTupField(..) => println!("ExprTupField"),
            ExprIndex(..) => println!("ExprIndex"),
            ExprPath(ref path) => {
                println!("ExprPath");
                match *path {
                    QPath::Resolved(ref ty, ref path) => {
                        // https://manishearth.github.io/rust-internals-docs
                        path.x();
                        println!("Resolved: {:?} - {:?}", ty, path);
                    },
                    QPath::TypeRelative(ref a, ref b) => {
                        println!("TypeRelative: {:?} - {:?}", a, b);
                    }
                }
            },
            ExprAddrOf(..) => println!("ExprAddrOf"),
            ExprBreak(..) => println!("ExprBreak"),
            ExprAgain(..) => println!("ExprAgain"),
            ExprRet(..) => println!("ExprRet"),
            ExprInlineAsm(..) => println!("ExprInlineAsm"),
            ExprStruct(..) => println!("ExprStruct"),
            ExprRepeat(..) => println!("ExprRepeat"),
        }
    }


    if_let_chain! {[
        let Some(arg) = args.get(arg_no),
        let ExprLit(ref lit) = arg.node,
        let LitKind::Int(mode, ..) = lit.node
    ], {
        return Some((mode as u32, arg.span));
    }}
    None
}

fn check_mode_validity(cx: &LateContext, span: Span, mode: u32) {
    if mode > 0o7777 {
        span_help_and_lint(cx,
                           INVALID_FILE_MODE,
                           span,
                           "file mode invalid",
                           "consider using …");
    }
}

fn check_world_writable_mode(cx: &LateContext, span: Span, mode: u32) {
    if mode & 0o002 != 0 {
        span_help_and_lint(cx,
                           WORLD_WRITABLE_FILE_MODE,
                           span,
                           "world-writable unix permissions",
                           "consider using …");
    }
}

fn check_world_readable_mode(cx: &LateContext, span: Span, mode: u32) {
    if mode & 0o004 != 0 {
        span_help_and_lint(cx,
                           WORLD_READABLE_FILE_MODE,
                           span,
                           "world-readable unix permissions",
                           "consider using …");
    }
}

fn check_setuid(cx: &LateContext, span: Span, mode: u32) {
    if mode & 0o6000 != 0 {
        span_help_and_lint(cx,
                           SETUID_FILE_MODE,
                           span,
                           "setuid or setgid set",
                           "consider using …");
    }
}
