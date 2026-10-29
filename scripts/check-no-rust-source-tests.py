#!/usr/bin/env python3
import pathlib
import re
import subprocess
import sys

CALL = re.compile(r"\b(?:include_(?:str|bytes)!|read_to_string)\s*\(")
TOKEN = re.compile(
    r'//[^\n]*|/\*.*?\*/|r(?P<hashes>\#*)".*?"(?P=hashes)|"(?:\\.|[^"\\])*"|[()]',
    re.DOTALL,
)


def source_reads(text):
    for call in CALL.finditer(text):
        depth = 1
        for token in TOKEN.finditer(text, call.end()):
            value = token.group()
            if value == "(":
                depth += 1
            elif value == ")":
                depth -= 1
                if depth == 0:
                    break
            elif value.startswith(('"', 'r"', 'r#')) and (
                "src/" in value or re.search(r'\.rs"', value)
            ):
                yield text.count("\n", 0, call.start()) + 1
                break


def self_test():
    for expression in [
        'include_str!("../src/lib.rs")',
        'include_str!(\n    "../src/lib.rs"\n)',
        'include_bytes!(\n    r#"../src/lib.rs"#\n)',
        'fs::read_to_string(\n    root.join("src/lib.rs"),\n)',
        'fs::read_to_string(format!("{}/src/{name}", root))',
        'fs::read_to_string(/* ) */ root.join("src/lib.rs"))',
    ]:
        assert list(source_reads(expression)), expression
    for expression in [
        'include_str!("fixtures/key.pem")',
        'fs::read_to_string(root.join("data.json")); let path = "src/lib.rs";',
        'include_str!("data.json")\n    .contains("src/lib.rs")',
        'read_to_string("data.json" /* src/lib.rs */)',
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
