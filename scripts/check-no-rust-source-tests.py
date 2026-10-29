#!/usr/bin/env python3
import bisect
import pathlib
import re
import subprocess
import sys

# API references make the file-level rule independent of aliases and generics.
READ_APIS = {
    "read",
    "read_to_string",
    "read_to_end",
    "open",
    "include_str!",
    "include_bytes!",
}
INCLUDE_MACROS = {"include_str", "include_bytes"}  # `name ! (` split over tokens
TOKEN = re.compile(
    r'//[^\n]*|/\*'
    r'|r(?P<hashes>\#*)".*?"(?P=hashes)'
    r'|"(?:\\.|[^"\\])*"'
    r"|'(?:\\.|[^'\\])'"
    r'|#\['
    r'|[A-Za-z_][A-Za-z0-9_]*!?'
    r'|.',
    re.DOTALL,
)
COMMENT_DELIMITER = re.compile(r"/\*|\*/")


def source_reads(text):
    """Yield a line number if the file reads Rust implementation source.

    Conservative file-level lexical rule: a file fails when a string
    literal names a Rust source path — a ``*.rs`` name, or a ``src/``
    component ending in ``.rs`` or carrying ``{...}`` placeholders —
    anywhere outside comments, ``#[path = "..."]`` attributes and
    ``include!`` arguments — ``include!`` accepts ``()``, ``{}`` or
    ``[]`` and compiles code rather than inspecting it — and the file
    also references a file-reading API. An API reference is a call,
    a qualified path (``fs::read``, ``x.read(...)``) or an import —
    a bare binding or field named ``read`` does not count. This is
    not dataflow analysis: a source path assigned to a variable long
    before the read is caught, and a source path sharing a file with
    an unrelated read is rejected on purpose.
    """
    newlines = [m.start() for m in re.finditer("\n", text)]
    first_path = None
    reads_files = False
    delims = []  # expected closers for every ( [ {
    include_frames = []  # delims index of each open include!(/{/[ argument
    want_include_open = False
    in_attr = path_attr = suppress_next = hash_pending = False
    in_use = fn_pending = pending_colon = False
    pending_api = None  # API identifier waiting for a ( or :: follower
    prev_sig = prev_sig2 = None
    position = 0
    while position < len(text):
        match = TOKEN.match(text, position)
        position = match.end()
        tok = match.group()
        if tok == "/*":
            nesting = 1
            while nesting:
                marker = COMMENT_DELIMITER.search(text, position)
                if marker is None:
                    position = len(text)
                    break
                nesting += 1 if marker.group() == "/*" else -1
                position = marker.end()
            continue
        if tok.isspace() or tok.startswith("//"):
            continue
        if pending_api is not None:
            if pending_colon:
                if tok == ":":
                    reads_files = True
                pending_api = None
                pending_colon = False
            elif tok == "(":
                reads_files = True
                pending_api = None
            elif tok == ":":
                pending_colon = True
            elif tok == "!" and pending_api in INCLUDE_MACROS:
                reads_files = True
                pending_api = None
            else:
                pending_api = None
        if hash_pending and tok not in ("!", "["):
            hash_pending = False
        if want_include_open and tok not in ("!", "(", "[", "{"):
            want_include_open = False
        if suppress_next and '"' not in tok:
            suppress_next = False
        if fn_pending:
            fn_pending = False
            if tok[:1].isalpha() or tok[:1] == "_":
                prev_sig2, prev_sig = prev_sig, tok
                continue
        if tok in ("(", "[", "{"):
            closer = {"(": ")", "[": "]", "{": "}"}[tok]
            delims.append(closer)
            if tok == "[" and hash_pending:
                in_attr = True
                path_attr = False
            if want_include_open:
                include_frames.append(len(delims) - 1)
                want_include_open = False
        elif tok == "#[":
            in_attr = True
            path_attr = False
            delims.append("]")
        elif tok in (")", "]", "}"):
            if delims and delims[-1] == tok:
                delims.pop()
                if include_frames and include_frames[-1] == len(delims):
                    include_frames.pop()
            if tok == "]":
                in_attr = path_attr = False
        elif tok == "#":
            hash_pending = True
        elif tok == "=":
            suppress_next = path_attr
        elif '"' in tok:
            body = tok[tok.index('"') + 1 : tok.rindex('"')]
            if (
                not suppress_next
                and not include_frames
                and first_path is None
                and (body.endswith(".rs") or ("src/" in body and "{" in body))
            ):
                first_path = bisect.bisect_right(newlines, match.start()) + 1
            suppress_next = False
        elif tok in ("include_str!", "include_bytes!"):
            reads_files = True
        elif tok in READ_APIS or tok in INCLUDE_MACROS:
            if in_use or (prev_sig == ":" and prev_sig2 == ":"):
                reads_files = True
            else:
                pending_api = tok
        elif tok == "include!" or tok == "include":
            want_include_open = True
        elif tok == "use":
            in_use = True
        elif tok == ";":
            in_use = False
        elif tok == "fn":
            fn_pending = True
        elif in_attr and tok == "path":
            path_attr = True
        prev_sig2, prev_sig = prev_sig, tok
    if first_path is not None and reads_files:
        yield first_path


def self_test():
    for expression in [
        'include_str!("../src/lib.rs")',
        'include_str!(\n    "../src/lib.rs"\n)',
        'include_str ! ("../src/lib.rs")',
        'include_bytes!(\n    r#"../src/lib.rs"#\n)',
        'fs::read_to_string(\n    root.join("src/lib.rs"),\n)',
        'fs::read_to_string(format!("{}/src/{name}", root))',
        'fs::read_to_string(/* ) */ root.join("src/lib.rs"))',
        'std::fs::read("../src/http.rs")',
        'std::fs::read(\n    "../src/http.rs",\n)',
        'File::open("../src/http.rs")',
        'std::fs::read::<_>("src/lib.rs")',
        'std::fs::read_to_string::<_>("src/lib.rs")',
        'File::open::<_>("src/lib.rs")',
        'let load = std::fs::read::<std::path::PathBuf>; load("src/lib.rs".into())',
        'use std::fs::read as load; load("src/lib.rs")',
        'OpenOptions::new().read(true).open("src/lib.rs")',
        'let mut buf = Vec::new();\n    File::open("lib.rs")?.read_to_end(&mut buf)',
        'let path = root.join("src/lib.rs");\n    fs::read_to_string(path)',
        'fs::read(root.join("src").join("http.rs"))',
        # Conservative on purpose: the source path and the read only have
        # to coexist in one file, not feed each other.
        'fs::read("data.json");\n    let path = "src/lib.rs";',
        'let expected = "src/lib.rs";\n    File::open("data.json")',
        'include_str!("data.json")\n    .contains("src/lib.rs")',
        'include_str!{"../src/lib.rs"}',
        'include_bytes![r#"../src/lib.rs"#]',
        'include_str ! { "../src/lib.rs" }',
        'use std::fs::{read, write};\n    read("src/lib.rs")',
    ]:
        assert list(source_reads(expression)), expression
    for expression in [
        'include_str!("fixtures/key.pem")',
        'fs::read_to_string(root.join("data.json"))',
        'File::open("fixtures/cert.pem")',
        'let mut f = File::open("config.yaml")?;\n    f.read_to_end(&mut buf)',
        'read_to_string("data.json" /* src/lib.rs */)',
        '// do not read src/lib.rs\n    fs::read("data.json")',
        '/* File::open("../src/lib.rs") */\n    fs::read("data.json")',
        'fs::read("data.json"); /* outer /* nested */ "src/lib.rs" */',
        '/* outer " /* nested */ "src/lib.rs" */ fs::read("data.json");',
        'let doc = "File::open(path) and fs::read(path)";\n    let name = "lib.rs";',
        'assert!(readme.contains("src/lib.rs"))',
        '#[path = "dir/extra.rs"]\n    mod extra;\n    fs::read("data.json")',
        '#[cfg_attr(test, path = "dir/extra.rs")]\n    mod extra;\n    File::open("data.json")',
        'fs::read_to_string(root.join("ui/src/routes/+page.svelte"))',
        'include!("generated.rs");\n    fs::read_to_string("data.json")',
        'include!(\n    "../generated.rs"\n);\n    File::open("data.json")',
        'include!(concat!(env!("OUT_DIR"), "/x.rs"));\n    fs::read("data.json")',
        'fs::read("data.json");\n    let path = "lib.rs.txt";',
        'fn read(p: &str) {}\n    read("data.json")',
        'include!{"../generated.rs"}\n    fs::read("data.json")',
        'include![concat!(env!("OUT_DIR"), "/x.rs")];\n    fs::read("data.json")',
        'include!/* c */{ "src/gen.rs" }\n    fs::read("data.json")',
        'let read = false;\n    let expected = "src/lib.rs";',
        'let s = S { read: false };\n    let expected = "src/lib.rs";',
        'let b = a.read;\n    let expected = "src/lib.rs";',
        'let f: read = g;\n    let expected = "src/lib.rs";',
        'fn read_to_string(p: &str) {}\n    let expected = "src/lib.rs";',
        '// include_str!("src/lib.rs")\n    fs::read("data.json")',
        '/* include_bytes!["src/lib.rs"] */\n    fs::read("data.json")',
        'let doc = "include_str!(\\"src/lib.rs\\")";\n    fs::read("data.json")',
    ]:
        assert not list(source_reads(expression)), expression
    print("source-read checker self-test passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        paths = subprocess.check_output(["git", "ls-files", "-z", "--", "*.rs"])
        violations = []
        for raw_path in paths.split(b"\0"):
            if raw_path:
                path = pathlib.Path(raw_path.decode())
                violations.extend(f"{path}:{line}" for line in source_reads(path.read_text()))
        if violations:
            print("Test runtime behavior instead of reading Rust implementation source:")
            print("\n".join(violations))
            sys.exit(1)
