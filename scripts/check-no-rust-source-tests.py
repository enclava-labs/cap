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
    ``include!(...)`` arguments — those compile code rather than inspect
    it — and the file also references a file-reading API. This is not
    dataflow analysis: a source path assigned to a variable long before
    the read is caught, and a source path sharing a file with an
    unrelated read is rejected on purpose.
    """
    newlines = [m.start() for m in re.finditer("\n", text)]
    first_path = None
    reads_files = False
    depth = 0
    include_depths = []  # paren depths of open include!( ... ) calls
    want_include_paren = False
    in_attr = path_attr = suppress_next = hash_pending = False
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
        if hash_pending and tok not in ("!", "["):
            hash_pending = False
        if want_include_paren and tok not in ("!", "("):
            want_include_paren = False
        if suppress_next and '"' not in tok:
            suppress_next = False
        if tok == "(":
            depth += 1
            if want_include_paren:
                include_depths.append(depth)
                want_include_paren = False
        elif tok == ")":
            if include_depths and depth == include_depths[-1]:
                include_depths.pop()
            depth -= 1
        elif tok == "#[" or (tok == "[" and hash_pending):
            in_attr = True
            path_attr = False
        elif tok == "#":
            hash_pending = True
        elif tok == "]":
            in_attr = path_attr = False
        elif tok == "=":
            suppress_next = path_attr
        elif '"' in tok:
            body = tok[tok.index('"') + 1 : tok.rindex('"')]
            if (
                not suppress_next
                and not include_depths
                and first_path is None
                and (body.endswith(".rs") or ("src/" in body and "{" in body))
            ):
                first_path = bisect.bisect_right(newlines, match.start()) + 1
            suppress_next = False
        elif tok in READ_APIS or tok in INCLUDE_MACROS:
            reads_files = True
        elif tok == "include!" or tok == "include":
            want_include_paren = True
        elif in_attr and tok == "path":
            path_attr = True
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
