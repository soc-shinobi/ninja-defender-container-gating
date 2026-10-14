"""Static integrity checks for the control panel.

WHY THIS EXISTS
---------------
Twice in this repo an index/slice-based patch to app/webapp/app.py silently
deleted a helper that was still being called. The second time it was
`_end_user()`: the chat route called it, nothing defined it, and the failure
only appeared at runtime as a NameError in front of an audience.

These checks are deliberately STATIC (ast only, no imports, no Flask, no
Azure SDK), so they run anywhere with a bare python3 and cannot be skipped
because a dependency is missing.

Run:  make test        (or)  python3 tests/test_app_integrity.py
"""
import ast
import builtins
import os
import re
import pathlib
import shutil
import subprocess
import sys
import tempfile

APP = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else (
    pathlib.Path(__file__).resolve().parent.parent / "app" / "webapp" / "app.py"
)

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  ok    {message}")
    else:
        print(f"  FAIL  {message}")
        failures.append(message)


def collect_bound_names(tree: ast.AST) -> set[str]:
    """Every name the module itself defines, imports or binds at any scope."""
    bound = set(dir(builtins))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
            for a in getattr(node, "args", ast.arguments(
                posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[])).posonlyargs \
                    + node.args.args + node.args.kwonlyargs if isinstance(
                        node, (ast.FunctionDef, ast.AsyncFunctionDef)) else []:
                bound.add(a.arg)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.args.vararg:
                    bound.add(node.args.vararg.arg)
                if node.args.kwarg:
                    bound.add(node.args.kwarg.arg)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, (ast.comprehension,)):
            pass
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.Global) or isinstance(node, ast.Nonlocal):
            bound.update(node.names)
    return bound


def main() -> int:
    source = APP.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(APP))

    print("app/webapp/app.py integrity")

    # 1. THE REGRESSION GUARD: nothing may be CALLED that is not DEFINED.
    bound = collect_bound_names(tree)
    called_undefined = sorted({
        n.func.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id not in bound
    })
    check(not called_undefined,
          f"every called name is defined (undefined: {called_undefined or 'none'})")

    # 2. The specific helper that was deleted twice.
    defined = {n.name for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for helper in ("_end_user", "_require_basic_auth", "_api_key_ok", "cluster_ca_file",
                   "allowed", "expand_alias", "command_library", "k8s", "_sim_job",
                   "_sim_stream", "_errors_as_output", "k8s_api_client",
                   "_parse_denial", "_admission_denials", "_flux_object"):
        check(helper in defined, f"{helper}() is still defined")

    # 3. Auth must not regress into something trivially bypassable.
    check("hmac" in {a.name for n in ast.walk(tree)
                     if isinstance(n, ast.Import) for a in n.names},
          "hmac is imported (constant-time credential compare)")
    check("compare_digest" in source,
          "credentials are compared with hmac.compare_digest, not ==")
    check("BASIC_AUTH_PASSWORD" in source,
          "password is read from the BASIC_AUTH_PASSWORD env var (an ACA secretRef)")

    # A non-empty fallback would silently defeat the whole mode: if the secret
    # never arrives, the app must refuse logins, not accept a known password.
    defaults = re.findall(r"""BASIC_AUTH_PASSWORD["']\s*,\s*["']([^"']*)["']""", source)
    check(all(d == "" for d in defaults),
          f"no hardcoded default password (defaults found: {defaults})")

    # 3b. API-key auth: same rules as the password. An unset key must lock the door, and
    # the key may only unlock /api/*, never the HTML console.
    check("PANEL_API_KEY" in source,
          "the API key is read from the PANEL_API_KEY env var (an ACA secretRef)")
    api_defaults = re.findall(r"""PANEL_API_KEY["']\s*,\s*["']([^"']*)["']""", source)
    check(all(d == "" for d in api_defaults),
          f"no hardcoded default API key (defaults found: {api_defaults})")
    key_fn = next((n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "_api_key_ok"), None)
    key_src = ast.get_source_segment(source, key_fn) if key_fn else ""
    check("compare_digest" in key_src,
          "the API key is compared with hmac.compare_digest, not ==")
    check("if not API_KEY" in key_src,
          "an empty API key can never authenticate")
    hook = next((n for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.name == "_require_basic_auth"), None)
    hook_src = ast.get_source_segment(source, hook) if hook else ""
    check("API_PREFIX" in hook_src and "_api_key_ok" in hook_src,
          "the key is only accepted on API_PREFIX paths")

    # 3c. THE PAGE SCRIPT MUST SURVIVE THE PYTHON STRING.
    # PAGE is a plain (non-raw) triple-quoted string, so a JS escape written as '\n' is
    # consumed by PYTHON and the browser receives a real newline inside a JS string literal.
    # That is a SyntaxError, and one of them kills the ENTIRE script: no console output, no
    # tables, no buttons - a page that looks fine and does nothing.
    page = next((n.value.value for n in tree.body
                 if isinstance(n, ast.Assign)
                 and getattr(n.targets[0], "id", "") == "PAGE"), "")
    script = re.findall(r"<script>(.*?)</script>", page, re.S)
    check(bool(script), "PAGE contains a script block")
    # A ' or " string must close on the line it opened: a real newline inside one is the
    # Python-escape bug. Backtick template literals may legally span lines, so this walks
    # the script tracking which kind of string it is inside rather than counting per line.
    def unclosed_string_lines(js: str) -> list[str]:
        bad, i, line, col_start = [], 0, 1, 0
        quote = None            # the character that opened the current string, or None
        while i < len(js):
            ch = js[i]
            if quote and ch == "\\":
                i += 2
                continue
            if ch == "\n":
                if quote in ("'", '"'):
                    bad.append(f"line {line}: {js[col_start:i].strip()[:60]}")
                    quote = None
                line += 1
                col_start = i + 1
            elif quote:
                if ch == quote:
                    quote = None
            elif ch in "'\"`":
                quote = ch
            i += 1
        return bad

    unbalanced = unclosed_string_lines(script[-1] if script else "")
    check(not unbalanced,
          f"every JS string literal closes on its own line (offenders: {unbalanced[:3] or 'none'})")

    # 3d. If node is around, let it parse the script for real. The quote check above catches
    # the string-literal break; only a parser catches a mangled regex or a stray bracket.
    if script:
        node = shutil.which("node")
        if node:
            js = re.sub(r"\{%.*?%\}", "", script[-1], flags=re.S)
            js = re.sub(r"\{\{.*?\}\}", "0", js)
            with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                             encoding="utf-8") as fh:
                fh.write(js)
                tmp = fh.name
            proc = subprocess.run([node, "--check", tmp], capture_output=True, text=True)
            os.unlink(tmp)
            first = (proc.stderr.strip().splitlines() or [""])[-1]
            check(proc.returncode == 0, f"node parses the page script ({first or 'clean'})")
        else:
            print("  skip  node not installed, skipping the real JS parse")

    # 3e. The alias must be resolved BEFORE the allowlist, or 'k get pods' is judged as the
    # unknown binary 'k' and refused in readonly mode.
    exec_fn = next((n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "api_exec"), None)
    exec_src = ast.get_source_segment(source, exec_fn) if exec_fn else ""
    check("expand_alias" in exec_src
          and exec_src.index("expand_alias") < exec_src.index("allowed("),
          "api_exec expands the alias before it checks the allowlist")

    # 4. The before_request hook must actually be registered as one.
    hooked = any(
        isinstance(n, ast.FunctionDef)
        and n.name == "_require_basic_auth"
        and any(getattr(d, "attr", None) == "before_request" for d in n.decorator_list)
        for n in ast.walk(tree)
    )
    check(hooked, "_require_basic_auth is registered with @app.before_request")

    # 5. Only the health probe may be exempt from auth.
    open_paths = [n for n in ast.walk(tree)
                  if isinstance(n, ast.Assign)
                  and any(getattr(t, "id", "") == "OPEN_PATHS" for t in n.targets)]
    check(len(open_paths) == 1, "OPEN_PATHS is defined exactly once")
    if open_paths:
        literal = ast.literal_eval(open_paths[0].value)
        check(set(literal) == {"/healthz"},
              f"only /healthz bypasses auth (found: {sorted(literal)})")

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
