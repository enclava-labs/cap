#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT_DIR/.github/workflows/api-image.yml"
DOCKERFILE="$ROOT_DIR/crates/enclava-api/Dockerfile"
COMPOSE="$ROOT_DIR/docker-compose.yml"
DEPLOYMENT="$ROOT_DIR/deploy/api/deployment.yaml"
KUSTOMIZATION="$ROOT_DIR/deploy/api/kustomization.yaml"
RBAC="$ROOT_DIR/deploy/api/rbac.yaml"

fail() {
  echo "error: $*" >&2
  exit 1
}

assert_contains() {
  grep -Fq -- "$1" "$WORKFLOW" || fail "workflow is missing: $1"
}

assert_order() {
  local first="$1"
  local second="$2"
  local first_line
  local second_line
  first_line="$(grep -nF -- "$first" "$WORKFLOW" | head -n1 | cut -d: -f1 || true)"
  second_line="$(grep -nF -- "$second" "$WORKFLOW" | head -n1 | cut -d: -f1 || true)"
  [[ -n "$first_line" && -n "$second_line" && "$first_line" -lt "$second_line" ]] \
    || fail "workflow order must keep '$first' before '$second'"
}

job_block() {
  local job="$1"
  local next="$2"
  awk -v start="  $job:" -v stop="  $next:" '
    $0 == start { active = 1 }
    $0 == stop { active = 0 }
    active { print }
  ' "$WORKFLOW"
}

unpinned="$(
  grep -nE '^[[:space:]]+- uses: ' "$WORKFLOW" \
    | grep -Ev '@[0-9a-f]{40}([[:space:]]+#|[[:space:]]*$)' \
    || true
)"
[[ -z "$unpinned" ]] || {
  echo "$unpinned" >&2
  fail "all workflow actions must be pinned to 40-character commits"
}

validate_block="$(job_block validate publish)"
publish_block="$(job_block publish "")"

for required in \
  "workflow_dispatch:" \
  "version_tag:" \
  "validate:" \
  "publish:" \
  "if: github.event_name == 'pull_request'" \
  "if: github.event_name == 'workflow_dispatch' || (github.event_name != 'pull_request' && (github.ref == 'refs/heads/main' || github.ref_type == 'tag'))" \
  "contents: read" \
  "id-token: write" \
  "packages: write" \
  "target: runtime-debug" \
  "push: false" \
  "push: true" \
  "target: runtime-release" \
  "ghcr.io/enclava-labs/enclava-api" \
  "dist/enclava-api-image.txt" \
  "dist/enclava-api-migration.txt" \
  "dist/enclava-api-signer-identity.txt" \
  'WORKFLOW_REF: ${{ github.workflow_ref }}' \
  'signer_subject="https://github.com/$WORKFLOW_REF"' \
  'IMAGE_DIGEST: ${{ steps.build.outputs.digest }}' \
  'image_ref="ghcr.io/enclava-labs/enclava-api@${IMAGE_DIGEST}"' \
  'PUSHED_REF: ${{ github.ref }}' \
  'refs/tags/v[A-Za-z0-9][A-Za-z0-9._-]*$' \
  "cosign sign --yes" \
  "scripts/verify-api-image-ref.sh --cosign dist/enclava-api-image.txt" \
  "name: enclava-api-release-manifest" \
  "scripts/test-api-image-workflow.sh" \
  "scripts/require-platform-release-root.sh" \
  "scripts/test-verify-api-image-ref.sh" \
  "scripts/verify-api-image-ref.bash" \
  "sh -n scripts/verify-api-image-ref.sh" \
  "bash -n scripts/verify-api-image-ref.bash"; do
  assert_contains "$required"
done

# No template interpolation may appear inside a `run:` block body (#226):
# values influenced by ref content or dispatch inputs must reach the shell
# only through an `env:` binding (runner-set, never shell-parsed). This guards
# against direct interpolation being reintroduced anywhere in the workflow,
# not just drift of the exact lines fixed above. Any `run:` value counts —
# literal blocks (|), folded blocks (>), single-line scalars, and multi-line
# continuation lines indented deeper than the `run:` key. The key is matched
# after stripping an optional sequence marker, so the `- run: cmd` shorthand
# (valid GitHub Actions syntax, already used in fuzz.yml) is covered, and
# quoted forms like "run": and 'run': are matched since YAML permits quoted
# mapping keys. Flow-style steps (`- { run: ... }`, `- [{ run: ... }]`, or a
# flow collection under a block key like `steps: [{ ... }]`) are parsed by
# YAML as ordinary run commands, so the guard walks flow collections
# quote-/depth-aware, splits entries on commas at the collection's own depth,
# and applies the same run-key matching to each entry - a sibling `env:`
# entry with a safe binding is not part of the command and stays unflagged.
# POSIX awk only (no interval expressions) so the guard also works under BWK awk on macOS.
scan_workflow() {
  awk -v mode="$1" -v q="'" '
    function indent(line) { return match(line, /[^[:space:]]/) - 1 }
    function runkey(line,  k) {
      k = line
      sub(/^[[:space:]]*/, "", k)
      sub(/^-[[:space:]]*/, "", k)
      if (k ~ /^"run"[[:space:]]*:/) sub(/^"run"[[:space:]]*/, "", k)
      else if (k ~ ("^" q "run" q "[[:space:]]*:")) sub(("^" q "run" q "[[:space:]]*"), "", k)
      else if (k ~ /^run[[:space:]]*:/) sub(/^run:[[:space:]]*/, "", k)
      else return ""
      return k
    }
    # --- flow collections -------------------------------------------------
    # YAML parses flow-style steps (- { run: ... }, steps: [{ ... }], a flow
    # mapping nested anywhere in a job value, multi-line variants) as
    # ordinary run commands, so closed flow collections are parsed
    # recursively: items split on commas at their own depth, a whole-item
    # or value-position nested collection recurses, and every mapping entry
    # goes through the same run-key checks as block mode. Quotes follow the
    # YAML rule that a quote only opens at a scalar start (after start,
    # comma, bracket, brace, colon, or dash), so an apostrophe inside a
    # plain scalar (name: dont-quote-me shapes) is literal text while a
    # genuinely quoted scalar may span lines; a collection still open at
    # EOF fails closed via the END block. Comments (a hash at line start or
    # after whitespace, outside quotes) end the scanned region of a line.
    # yaml_plain blanks quoted spans and comment tails so the anchor/alias
    # regex only ever sees plain text.
    function yaml_plain(text,  i, c, out, quote, prevsig) {
      out = ""; quote = ""; prevsig = ""
      for (i = 1; i <= length(text); i++) {
        c = substr(text, i, 1)
        if (quote != "") {
          out = out " "
          if (quote == "\"" && c == "\\") { i++; continue }
          if (c == quote) {
            if (quote == q && substr(text, i + 1, 1) == q) { i++; continue }
            quote = ""; prevsig = c
          }
          continue
        }
        if (c == "#" && (i == 1 || substr(text, i - 1, 1) ~ /[[:space:]]/)) return out
        if ((c == q || c == "\"") && (prevsig == "" || prevsig == "," || prevsig == "[" || prevsig == "{" || prevsig == ":" || prevsig == "-")) {
          quote = c
          out = out " "
          continue
        }
        out = out c
        if (c != " " && c != "\t") prevsig = c
      }
      return out
    }
    # Scan one line of an open flow collection. Returns the column of the
    # closing bracket when the collection closes, the negated column of a
    # comment start when the line ends in a comment, and 0 when the
    # collection continues. fdepth/fquote/fsig persist across lines so
    # multi-line quoted scalars keep their state.
    function flow_scan_line(line,  i, c) {
      for (i = 1; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (fquote != "") {
          if (fquote == "\"" && c == "\\") { i++; continue }
          if (c == fquote) {
            if (fquote == q && substr(line, i + 1, 1) == q) { i++; continue }
            fquote = ""
          }
          continue
        }
        if (c == "#" && (i == 1 || substr(line, i - 1, 1) ~ /[[:space:]]/)) return -i
        if ((c == q || c == "\"") && (fsig == "" || fsig == "," || fsig == "[" || fsig == "{" || fsig == ":" || fsig == "-")) {
          fquote = c
          continue
        }
        if (c == "{" || c == "[") { fdepth++; fsig = c; continue }
        if (c == "}" || c == "]") {
          fdepth--
          if (fdepth <= 0) return i
          fsig = c
          continue
        }
        if (c != " " && c != "\t") fsig = c
      }
      return 0
    }
    # Column of the first flow opener outside quotes and comments, else 0.
    function flow_find(text,  i, c, quote) {
      quote = ""
      for (i = 1; i <= length(text); i++) {
        c = substr(text, i, 1)
        if (quote != "") {
          if (quote == "\"" && c == "\\") { i++; continue }
          if (c == quote) {
            if (quote == q && substr(text, i + 1, 1) == q) { i++; continue }
            quote = ""
          }
          continue
        }
        if (c == "#" && (i == 1 || substr(text, i - 1, 1) ~ /[[:space:]]/)) return 0
        if (c == q || c == "\"") { quote = c; continue }
        if (c == "{" || c == "[") return i
      }
      return 0
    }
    # A flow collection is only walked when its opener plausibly starts a
    # YAML node: at line start, after an optional sequence marker, or right
    # after a block key (quoted keys included). In block context braces
    # inside a plain scalar (name: deploy{region}) are literal text.
    function flow_begin(line,  pos, pre) {
      pos = flow_find(line)
      if (pos == 0) return 0
      pre = substr(line, 1, pos - 1)
      if (pre ~ /^[[:space:]]*$/) return pos
      if (pre ~ /^[[:space:]]*-[[:space:]]+$/) return pos
      if (pre ~ /^[[:space:]]*-[[:space:]]*[A-Za-z0-9_.-]+:[[:space:]]*$/) return pos
      if (pre ~ /^[[:space:]]*[A-Za-z0-9_.-]+:[[:space:]]*$/) return pos
      if (pre ~ /^[[:space:]]*"[^"]*":[[:space:]]*$/) return pos
      if (pre ~ ("^[[:space:]]*" q "[^" q "]*" q ":[[:space:]]*$")) return pos
      return 0
    }
    # Split the inside of one collection into items on commas at depth 0,
    # quotes (scalar-start rule) respected.
    function flow_split(text, items,  i, c, quote, depth, cur, n, prev) {
      n = 0; quote = ""; depth = 0; cur = ""; prev = ""
      for (i = 1; i <= length(text); i++) {
        c = substr(text, i, 1)
        if (quote != "") {
          cur = cur c
          if (quote == "\"" && c == "\\") { cur = cur substr(text, i + 1, 1); i++; continue }
          if (c == quote) {
            if (quote == q && substr(text, i + 1, 1) == q) { cur = cur q; i++; continue }
            quote = ""
          }
          continue
        }
        if (c == q || c == "\"") {
          if (prev == "" || prev == "," || prev == "[" || prev == "{" || prev == ":" || prev == "-") quote = c
          cur = cur c
          if (quote == c) prev = c
          continue
        }
        if (c == "{" || c == "[") { depth++; cur = cur c; prev = c; continue }
        if (c == "}" || c == "]") { depth--; cur = cur c; prev = c; continue }
        if (c == "," && depth == 0) { items[++n] = cur; cur = ""; prev = ""; continue }
        cur = cur c
        if (c != " " && c != "\t") prev = c
      }
      if (cur != "") items[++n] = cur
      return n
    }
    # Recursively check a closed collection (text runs from its opening
    # bracket to its matching close).
    function flow_parse(text, fline,  inner, items, n, k) {
      inner = substr(text, 2, length(text) - 2)
      n = flow_split(inner, items)
      for (k = 1; k <= n; k++) flow_item(items[k], fline)
    }
    # Check one flow item: whole-item collections recurse, run-key entries
    # get the block-mode checks, other key/value entries recurse into a
    # collection-valued right side (steps: [{ ... }] at any depth).
    function flow_item(item, fline,  e, value, rest, pos, plain, lead) {
      e = item
      sub(/^[[:space:]]+/, "", e)
      sub(/[[:space:]]+$/, "", e)
      if (e == "") return
      if ((substr(e, 1, 1) == "{" && substr(e, length(e), 1) == "}") ||
          (substr(e, 1, 1) == "[" && substr(e, length(e), 1) == "]")) {
        flow_parse(e, fline)
        return
      }
      value = runkey(e)
      if (value != "") {
        if (mode == "run" && value ~ /\$\{\{/) print fline ": " e
        # A bare alias as the entire run value is resolved by YAML before
        # the shell sees the text, so ban it outright (same rule as block).
        if (mode == "anchors" && value ~ /^\*[^][[:space:]{},&*]/) print fline ": " e
        lead = value
        sub(/^[[:space:]]+/, "", lead)
        if (substr(lead, 1, 1) == "{" || substr(lead, 1, 1) == "[") flow_parse(lead, fline)
        return
      }
      pos = flow_keysep(e)
      if (pos > 0) {
        rest = substr(e, pos + 1)
        sub(/^[[:space:]]+/, "", rest)
        if (substr(rest, 1, 1) == "{" || substr(rest, 1, 1) == "[") flow_parse(rest, fline)
      }
      if (mode == "anchors") {
        plain = yaml_plain(e)
        if (plain ~ /(^|[[:space:]])[&*][^][[:space:]{},&*]/) print fline ": " e
      }
    }
    # Column of the key/value separator colon of a flow item (a colon
    # followed by space or a flow indicator, outside quotes and nesting).
    function flow_keysep(e,  i, c, nc, quote, depth) {
      quote = ""; depth = 0
      for (i = 1; i < length(e); i++) {
        c = substr(e, i, 1)
        if (quote != "") {
          if (quote == "\"" && c == "\\") { i++; continue }
          if (c == quote) {
            if (quote == q && substr(e, i + 1, 1) == q) { i++; continue }
            quote = ""
          }
          continue
        }
        if (c == q || c == "\"") { quote = c; continue }
        if (c == "{" || c == "[") depth++
        else if (c == "}" || c == "]") depth--
        else if (c == ":" && depth == 0) {
          # Portable separator test (busybox awk does not honor \\[ and
          # \\] inside a bracket expression, so compare characters
          # directly): a flow key/value colon is followed by whitespace,
          # a comma, or a flow indicator, or ends the item.
          nc = substr(e, i + 1, 1)
          if (i == length(e) || nc == " " || nc == "\t" || nc == "," || nc == "{" || nc == "}" || nc == "[" || nc == "]") return i
        }
      }
      return 0
    }
    # Locate the collection in a fully-buffered line group and parse it.
    function flow_start(text, fline,  p) {
      p = flow_find(text)
      if (p > 0) flow_parse(substr(text, p), fline)
    }
    {
      if (in_run) {
        if ($0 ~ /^[[:space:]]*$/) next
        if (indent($0) > run_indent) {
          if (mode == "run" && $0 ~ /\$\{\{/) print FNR ": " $0
          next
        }
        in_run = 0
      }
      if (in_flow) {
        if ($0 ~ /^[[:space:]]*$/) next
        cc = flow_scan_line($0)
        if (cc > 0) {
          fbuf = fbuf " " substr($0, 1, cc)
          flow_start(fbuf, fline)
          in_flow = 0
        } else if (cc < 0) {
          fbuf = fbuf " " substr($0, 1, -cc - 1)
        } else {
          fbuf = fbuf " " $0
        }
        next
      }
      value = runkey($0)
      if (value != "") {
        # run_indent is the column of the run key itself (indent + optional
        # "- " marker), so sibling step keys like env: at the same level end
        # the run body instead of being scanned as shell continuation text.
        k = $0
        sub(/^[[:space:]]*/, "", k)
        sub(/^-[[:space:]]*/, "", k)
        run_indent = length($0) - length(k)
        if (mode == "run" && value ~ /\$\{\{/) print FNR ": " $0
        # A bare alias as the entire run value (`run: *payload`) is resolved
        # by YAML before the shell ever sees the text, so ban it outright.
        # Anchor names follow the YAML grammar: any printable except
        # whitespace, flow indicators (, [ ] { }), and & or * themselves
        # (excluding & * keeps shell `&&`/`**` from matching); `]` first and
        # `[` last inside the bracket expression keep it POSIX-portable.
        if (mode == "anchors" && value ~ /^\*[^][[:space:]{},&*]/) print FNR ": " $0
        in_run = 1
      } else if ($0 !~ /^[[:space:]]*$/) {
        pos = flow_begin($0)
        if (pos > 0) {
          fline = FNR
          fdepth = 0
          fquote = ""
          fsig = ""
          in_flow = 1
          cc = flow_scan_line($0)
          if (cc > 0) {
            fbuf = substr($0, 1, cc)
            flow_start(fbuf, fline)
            in_flow = 0
          } else if (cc < 0) {
            fbuf = substr($0, 1, -cc - 1)
          } else {
            fbuf = $0
          }
        } else if (mode == "anchors") {
          plain = yaml_plain($0)
          if (plain ~ /(^|[[:space:]])[&*][^][[:space:]{},&*]/) print FNR ": " $0
        }
      }
    }
    END {
      # Fail closed: a flow collection still open at EOF cannot be walked
      # safely, so flag it instead of silently skipping the rest of the file.
      if (in_flow) print fline ": unclosed flow collection (run entries cannot be scanned safely)"
    }
  ' "$2"
}
scan_run_injections() { scan_workflow run "$1"; }

# GitHub Actions honors YAML anchors/aliases, so an interpolated scalar
# defined anywhere in the file (e.g. `SCRIPT: &unsafe echo "${{ github.ref }}"`
# under `env:`) could be laundered into `run: *unsafe`, where the raw-text
# scan above never sees the `${{ }}`. Scanning resolved values would require a
# full YAML parser in CI; this workflow uses no anchors, so anchor/alias
# tokens are rejected outright to keep the guard sound.
# Match valid YAML anchor/alias names: letters, underscores, digits (including
# leading digits like &1), excluding shell globs that appear only in run: bodies.
scan_anchor_tokens() { scan_workflow anchors "$1"; }

run_body_injections="$(scan_run_injections "$WORKFLOW")"
[[ -z "$run_body_injections" ]] || {
  echo "$run_body_injections" >&2
  fail "workflow interpolates \${{ ... }} directly inside a run: block; pass the value through an env: binding instead"
}
anchor_tokens="$(scan_anchor_tokens "$WORKFLOW")"
[[ -z "$anchor_tokens" ]] || {
  echo "$anchor_tokens" >&2
  fail "workflow must not use YAML anchors or aliases; an aliased scalar could carry \${{ ... }} into a run: command unscanned (write the env: binding out explicitly instead)"
}

# Self-tests: prove the guard flags every smuggling shape it claims to cover
# (inline scalar, folded block, plain-scalar continuation, aliased run) and
# stays silent for env:-bound values, so the coverage claim cannot silently
# regress.
guard_tmp="$(mktemp -d)"
guard_case() { printf '%s\n' "$2" >"$guard_tmp/$1.yml"; }
guard_must_flag_run() {
  [[ -n "$(scan_run_injections "$guard_tmp/$1.yml")" ]] \
    || fail "run-injection guard self-test ($1): interpolation must be flagged"
}

guard_case inline '        run: echo "${{ github.ref }}"
'
guard_must_flag_run inline
guard_case folded '        run: >
          echo "${{ github.ref }}"
'
guard_must_flag_run folded
guard_case continuation '        run: echo start
          and "${{ github.ref }}"
'
guard_must_flag_run continuation
guard_case aliased '        env:
          SCRIPT: &unsafe_script echo "${{ github.ref }}"
        run: *unsafe_script
'
[[ -n "$(scan_anchor_tokens "$guard_tmp/aliased.yml")" ]] \
  || fail "run-injection guard self-test (aliased): anchor/alias tokens must be flagged"
guard_case env-bound '        env:
          PUSHED_REF: ${{ github.ref }}
        run: |
          echo "$PUSHED_REF"
'
[[ -z "$(scan_run_injections "$guard_tmp/env-bound.yml")" ]] \
  || fail "run-injection guard self-test (env-bound): env: bindings must not be flagged"
[[ -z "$(scan_anchor_tokens "$guard_tmp/env-bound.yml")" ]] \
  || fail "run-injection guard self-test (env-bound): unexpected anchor/alias match"

# Numeric aliases like &1 and *1 are valid YAML (PRRT_kwDOSHSH5s6sKiuV)
guard_case numeric_alias '        env:
          SCRIPT: &1 echo "${{ github.ref }}"
        run: *1
'
[[ -n "$(scan_anchor_tokens "$guard_tmp/numeric_alias.yml")" ]] \
  || fail "run-injection guard self-test (numeric_alias): numeric anchor/alias tokens must be flagged"

# Quoted run keys like "run": are valid YAML (PRRT_kwDOSHSH5s6sKkHX)
guard_case quoted_run '        "run": echo "${{ github.ref }}"
'
guard_must_flag_run quoted_run

# Shell globs in run: bodies should NOT trigger anchor ban (PRRT_kwDOSHSH5s6KitB)
guard_case shell_glob '        run: ls -la *.txt
'
[[ -z "$(scan_anchor_tokens "$guard_tmp/shell_glob.yml")" ]] \
  || fail "run-injection guard self-test (shell_glob): shell globs in run: must not be flagged as anchors"

# Anchors on sequence-item key lines (`- name: &payload ...`) after a run:
# step must not escape the anchor ban: the in_run state must end at the
# shallower sequence-item line, not persist past it (Devin review, #236).
guard_case aliased_seq_item '        run: |
          echo "start"
        - name: &payload echo "${{ github.ref }}"
        - run: *payload
'
[[ -n "$(scan_anchor_tokens "$guard_tmp/aliased_seq_item.yml")" ]] \
  || fail "run-injection guard self-test (aliased_seq_item): anchors on sequence-item lines must be flagged"

# The `- run:` sequence-marker shorthand (valid GitHub Actions syntax, used
# in fuzz.yml) must not bypass either guard (Codex review, #236).
guard_case seq_marker_run '        - run: echo "${{ github.ref }}"
'
guard_must_flag_run seq_marker_run
guard_case seq_marker_run_block '        - run: |
            echo "${{ github.ref }}"
'
guard_must_flag_run seq_marker_run_block

# A sibling env: block after a `- run:` shorthand is the safe pattern and
# must NOT be treated as shell continuation text (Devin/Codex, #236).
guard_case seq_marker_run_env '        - run: echo "$PUSHED_REF"
          env:
            PUSHED_REF: ${{ github.ref }}
'
[[ -z "$(scan_run_injections "$guard_tmp/seq_marker_run_env.yml")" ]] \
  || fail "run-injection guard self-test (seq_marker_run_env): sibling env: bindings after - run: must not be flagged"

# A bare alias as the entire run value is resolved before the shell sees the
# text, so the anchor scan must flag the alias line itself.
guard_case bare_alias_run '        run: *payload
'
[[ -n "$(scan_anchor_tokens "$guard_tmp/bare_alias_run.yml")" ]] \
  || fail "run-injection guard self-test (bare_alias_run): bare alias run value must be flagged"

# Punctuation anchor names (`&.`, `*-foo`) are valid YAML 1.2 and must be
# flagged, while shell `&&`/`||`/`**` in run bodies must not be (reviewer
# self-check on #236 follow-ups).
guard_case punct_anchor '        env:
          SCRIPT: &. echo "${{ github.ref }}"
        run: *.
'
[[ -n "$(scan_anchor_tokens "$guard_tmp/punct_anchor.yml")" ]] \
  || fail "run-injection guard self-test (punct_anchor): punctuation-named anchors must be flagged"
guard_case shell_operators '        run: make -j2 && ./test.sh || true
'
[[ -z "$(scan_anchor_tokens "$guard_tmp/shell_operators.yml")" ]] \
  || fail "run-injection guard self-test (shell_operators): shell operators in run: must not be flagged"

# Flow-style mappings/sequences are parsed by YAML as ordinary run commands
# (Codex review, #236): `- { run: ... }` must not bypass either guard.
guard_case flow_run '- { run: '"'"'echo "${{ github.ref }}"'"'"' }
'
guard_must_flag_run flow_run
guard_case flow_seq_run '- [{ run: "echo ${{ github.ref }}" }]
'
guard_must_flag_run flow_seq_run
guard_case flow_multiline '- {
     run: '"'"'echo
       "${{ github.ref }}"'"'"',
   }
'
guard_must_flag_run flow_multiline
guard_case flow_key_run 'steps: [{ run: "echo ${{ github.ref }}" }]
'
guard_must_flag_run flow_key_run
# A sibling env: entry inside the same flow mapping binds the value safely
# and must NOT be flagged as part of the command.
guard_case flow_env_safe '- { run: '"'"'echo "$PUSHED_REF"'"'"', env: { PUSHED_REF: "${{ github.ref }}" } }
'
[[ -z "$(scan_run_injections "$guard_tmp/flow_env_safe.yml")" ]] \
  || fail "run-injection guard self-test (flow_env_safe): flow env bindings must not be flagged"
# Anchor/alias tokens inside flow collections must still be flagged.
guard_case flow_anchor '- { run: *payload, env: { SCRIPT: &unsafe echo } }
'
[[ -n "$(scan_anchor_tokens "$guard_tmp/flow_anchor.yml")" ]] \
  || fail "run-injection guard self-test (flow_anchor): anchors/aliases in flow collections must be flagged"
# A flow collection left open at EOF must fail closed, not skip the file.
guard_case flow_unclosed '- { run: '"'"'echo "${{ github.ref }}"'"'"'
'
guard_must_flag_run flow_unclosed
[[ -n "$(scan_anchor_tokens "$guard_tmp/flow_unclosed.yml")" ]] \
  || fail "run-injection guard self-test (flow_unclosed): unclosed flow collections must fail closed"
# Braces inside plain scalars are literal text, not flow collections, and
# must not trip the walker (comment braces included).
guard_case flow_literal_scalar '        name: deploy{region} west # {not a flow}
        run: echo ok
'
[[ -z "$(scan_run_injections "$guard_tmp/flow_literal_scalar.yml")" ]] \
  || fail "run-injection guard self-test (flow_literal_scalar): literal braces in scalars must not be flagged"
[[ -z "$(scan_anchor_tokens "$guard_tmp/flow_literal_scalar.yml")" ]] \
  || fail "run-injection guard self-test (flow_literal_scalar): unexpected anchor/alias match"

# Re-review round on the flow walker (#236): recursion, quoting, comments.

# env siblings inside steps: [{ ... }] are safe bindings, not command text
# (Devin review): items split at their own depth, only run values checked.
guard_case flow_seq_env_safe 'steps: [{ run: '"'"'echo ok'"'"', env: { REF: '"'"'${{ github.ref }}'"'"' } }]
'
[[ -z "$(scan_run_injections "$guard_tmp/flow_seq_env_safe.yml")" ]] \
  || fail "run-injection guard self-test (flow_seq_env_safe): env bindings inside steps: [{ ... }] must not be flagged"

# A flow mapping nested in a job value is still parsed recursively so its
# run entry is checked (Codex review): depth is not an escape hatch.
guard_case flow_nested_job 'job: { runs-on: ubuntu-latest, steps: [{ name: exploit, run: '"'"'echo "${{ github.ref }}"'"'"' }] }
'
guard_must_flag_run flow_nested_job
guard_case flow_nested_job_safe 'job: { runs-on: ubuntu-latest, steps: [{ name: ok, run: '"'"'echo "$REF'"'"', env: { REF: '"'"'${{ github.ref }}'"'"' } }] }
'
[[ -z "$(scan_run_injections "$guard_tmp/flow_nested_job_safe.yml")" ]] \
  || fail "run-injection guard self-test (flow_nested_job_safe): nested safe env binding must not be flagged"

# Key order inside a flow mapping is irrelevant: name before run must not
# hide the run entry (Devin review).
guard_case flow_key_order 'steps: [{ name: deploy, run: '"'"'echo "${{ github.ref }}"'"'"' }]
'
guard_must_flag_run flow_key_order

# Quoted flow scalars may span lines (Devin review): the quote state
# persists across the collection's lines.
guard_case flow_multiline_quoted 'steps: [{run: "echo
  hi"}]
'
[[ -z "$(scan_run_injections "$guard_tmp/flow_multiline_quoted.yml")" ]] \
  || fail "run-injection guard self-test (flow_multiline_quoted): safe multiline quoted scalar must not be flagged"
guard_case flow_multiline_quoted_interp 'steps: [{run: "echo
  ${{ github.ref }}"}]
'
guard_must_flag_run flow_multiline_quoted_interp

# An apostrophe inside an unquoted plain scalar is literal text, not a
# quote opener (Devin review): quotes only open at a scalar start.
guard_case flow_plain_apostrophe 'steps: [{ name: dont panic, run: '"'"'echo ok'"'"' }]
'
[[ -z "$(scan_run_injections "$guard_tmp/flow_plain_apostrophe.yml")" ]] \
  || fail "run-injection guard self-test (flow_plain_apostrophe): plain scalar text must not be treated as quoting"
[[ -z "$(scan_anchor_tokens "$guard_tmp/flow_plain_apostrophe.yml")" ]] \
  || fail "run-injection guard self-test (flow_plain_apostrophe): unexpected anchor/alias match"

# Anchor-like text inside comments and quoted scalars must not trip the
# anchor/alias ban (Codex review).
guard_case flow_anchor_in_comment '        run: echo ok
        # Support R&D &security release naming
'
[[ -z "$(scan_anchor_tokens "$guard_tmp/flow_anchor_in_comment.yml")" ]] \
  || fail "run-injection guard self-test (flow_anchor_in_comment): anchor-like text in comments must not be flagged"
guard_case flow_anchor_in_quoted '        name: "R&D &friends"
        run: echo ok
'
[[ -z "$(scan_anchor_tokens "$guard_tmp/flow_anchor_in_quoted.yml")" ]] \
  || fail "run-injection guard self-test (flow_anchor_in_quoted): anchor-like text in quoted scalars must not be flagged"
rm -rf "$guard_tmp"

grep -Fq -- '      - "deploy/api/**"' "$WORKFLOW" \
  || fail "API manifest changes must trigger image validation"
grep -Fq -- "serviceAccountName: enclava-api" "$DEPLOYMENT" \
  || fail "API Deployment must use its Kubernetes reconciliation identity"
grep -Fq -- "automountServiceAccountToken: true" "$DEPLOYMENT" \
  || fail "API Deployment must mount Kubernetes credentials"
grep -A1 -F -- "name: DATABASE_MIGRATION_MODE" "$DEPLOYMENT" \
  | grep -Fq -- "value: verify" \
  || fail "API Deployment must leave migrations to the release Job"
[[ "$(grep -Fc -- "app.kubernetes.io/name: cap-api" "$DEPLOYMENT")" -ge 2 ]] \
  || fail "API Deployment and pod template must carry the tenant-policy CAP identity"
grep -Fq -- 'CAP_DISABLE_EDGE_RECONCILIATION: "true"' "$COMPOSE" \
  || fail "non-Kubernetes Compose must explicitly disable edge reconciliation"
grep -Fq -- 'CAP_DEPLOYMENT_DISPATCH_ENABLED: "false"' "$COMPOSE" \
  || fail "non-Kubernetes Compose must keep deployment dispatch disabled"
if grep -Fq -- "CAP_DISABLE_EDGE_RECONCILIATION" "$DEPLOYMENT"; then
  fail "release API Deployment must not disable edge reconciliation"
fi
grep -Fq -- "- rbac.yaml" "$KUSTOMIZATION" \
  || fail "API release manifest must include reconciliation RBAC"
if grep -Eq '^namespace:' "$KUSTOMIZATION"; then
  fail "API kustomization must preserve the tenant-envoy Role namespace"
fi
for required in \
  "kind: ServiceAccount" \
  "kind: Role" \
  "kind: RoleBinding" \
  "name: enclava-api-edge-reconciler" \
  "name: enclava-api-service-reader" \
  "namespace: tenant-envoy" \
  'resources: ["services"]' \
  'resources: ["configmaps"]' \
  'resources: ["pods"]' \
  'resources: ["daemonsets"]' \
  'resourceNames: ["haproxy-tenant"]' \
  'verbs: ["list"]' \
  'verbs: ["get", "update"]'; do
  grep -Fq -- "$required" "$RBAC" \
    || fail "API release RBAC is missing: $required"
done

for required in \
  "cargo build --locked --bin enclava-api --bin cap-migrate" \
  "COPY --from=debug-builder /usr/local/bin/cap-migrate /usr/local/bin/cap-migrate" \
  "cargo build --locked --release --bin enclava-api --bin cap-migrate --features prod-strict" \
  "COPY --from=release-builder /usr/local/bin/cap-migrate /usr/local/bin/cap-migrate" \
  "ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX" \
  "COPY scripts/require-platform-release-root.sh scripts/require-platform-release-root.sh" \
  "bash scripts/require-platform-release-root.sh --allow-dev-fixture" \
  "--example platform-release -- verify" \
  "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must be provided as a build-arg"; do
  grep -Fq -- "$required" "$DOCKERFILE" \
    || fail "API image Dockerfile is missing: $required"
done
if grep -Eq '^ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=' "$DOCKERFILE"; then
  fail "API Dockerfile must not default ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX"
fi
[[ "$(grep -cE '^ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX$' "$DOCKERFILE")" -eq 2 ]] \
  || fail "API Dockerfile must declare ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX with no default in both builder stages"
[[ "$(grep -cF 'ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must be provided as a build-arg' "$DOCKERFILE")" -eq 2 ]] \
  || fail "API Dockerfile must fail the build when the platform-release root is empty"
# The release builder must run the gate without the dev-fixture escape hatch.
[[ "$(grep -cE 'bash scripts/require-platform-release-root\.sh$' "$DOCKERFILE")" -eq 1 ]] \
  || fail "API Dockerfile release stage must run the strict root gate exactly once"
[[ "$(grep -cF 'COPY scripts/require-platform-release-root.sh' "$DOCKERFILE")" -eq 2 ]] \
  || fail "API Dockerfile must copy the root gate into both builder stages"

# The release image must ship the pinned sigstore trust root and point
# SIGSTORE_TUF_ROOT_PATH at it (cosign.rs fails closed in release builds
# without a file-backed root).
grep -Fq -- "COPY crates/enclava-api/trust-roots/sigstore-public-good-1.root.json /etc/enclava/sigstore/trusted_root.json" "$DOCKERFILE" \
  || fail "API Dockerfile release stage must bake in the pinned sigstore trust root"
grep -Fq -- "ENV SIGSTORE_TUF_ROOT_PATH=/etc/enclava/sigstore/trusted_root.json" "$DOCKERFILE" \
  || fail "API Dockerfile release stage must set SIGSTORE_TUF_ROOT_PATH"
grep -Fq -- "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66" "$DOCKERFILE" \
  || fail "API Dockerfile builder stages must sha256-gate the bundled trust root"
grep -Fq -- "value: /etc/enclava/sigstore/trusted_root.json" "$DEPLOYMENT" \
  || fail "deployment must restate SIGSTORE_TUF_ROOT_PATH explicitly"

grep -Fq -- "Local-compose-only well-known fixture; must never be a Dockerfile default." "$COMPOSE" \
  || fail "compose must label the fixture as local-compose-only"
grep -Fq -- "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX: 5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd" "$COMPOSE" \
  || fail "compose must pass the well-known local fixture as an explicit build-arg"
grep -Fq -- "target: runtime-debug" "$COMPOSE" \
  || fail "compose must build the debug stage, the only stage the fixture root may pin"

grep -Fq -- "Test-only well-known fixture; never a Dockerfile default. PR validation only." <<<"$validate_block" \
  || fail "PR validation must label the fixture as test-only"
grep -Fq -- "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd" <<<"$validate_block" \
  || fail "PR validation must pass the test-only fixture as an explicit build-arg"
grep -Fq -- "secrets.ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX" <<<"$publish_block" \
  || fail "publisher must pass secrets.ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX"
grep -Fq -- "secrets.ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON" <<<"$publish_block" \
  || fail "publisher must materialize the production envelope from secrets.ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON"
grep -Fq -- "scripts/require-platform-release-root.sh" <<<"$publish_block" \
  || fail "publisher must run the production platform-release root gate"
# Every pushed image is a prod-strict release build; the fixture-tolerant
# debug stage must never be published.
grep -Fq -- "target: runtime-release" <<<"$publish_block" \
  || fail "publisher must build the release stage"
if grep -Fq -- "runtime-debug" <<<"$publish_block"; then
  fail "publisher must not build or push the debug stage"
fi
if grep -Fq -- "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX=5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd" <<<"$publish_block"; then
  fail "publisher must not pass the committed fixture as a build-arg"
fi

ROOT_GATE="$ROOT_DIR/scripts/require-platform-release-root.sh"
bash -n "$ROOT_GATE" || fail "scripts/require-platform-release-root.sh is not valid bash"
[[ -x "$ROOT_GATE" ]] || fail "scripts/require-platform-release-root.sh must be executable"
grep -Fq -- '^[0-9a-f]{64}$' "$ROOT_GATE" \
  || fail "root gate must require a 32-byte hex pubkey"
grep -Fq -- "must not be the committed dev fixture pubkey" "$ROOT_GATE" \
  || fail "root gate must reject the committed fixture pubkey"
grep -Fq -- "must match the bundled envelope's signing_pubkey" "$ROOT_GATE" \
  || fail "root gate must reject a root that cannot verify the bundled envelope"

# Gate scenarios run against synthetic envelopes so the root/envelope
# rotation invariant is exercised independently of the committed fixture.
GATE_TMP="$(mktemp -d)"
trap 'rm -rf "$GATE_TMP"' EXIT
prod_key="0000000000000000000000000000000000000000000000000000000000000001"
other_key="0000000000000000000000000000000000000000000000000000000000000002"
write_envelope() {
  printf '{"signing_pubkey": "%s"}\n' "$1" >"$GATE_TMP/envelope.json"
}

# Passes the repo envelope so shape checks run against real bundled state.
repo_env=(ENCLAVA_PLATFORM_RELEASE_ENVELOPE="$ROOT_DIR/crates/enclava-cli/platform-release.json")

gate_rejects() {
  local value="$1"
  local reason="$2"
  if env "${repo_env[@]}" ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="$value" "$ROOT_GATE" \
    >/tmp/platform-release-root-gate.out 2>/tmp/platform-release-root-gate.err; then
    fail "root gate must reject $reason"
  fi
}
gate_rejects "" "an empty root"
gate_rejects "5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd" "the committed fixture"
gate_rejects "5B9437ADEAFFBE8F41B13D96ED49D2F51CD6C266CD8ECC284B0552EC4912B8DD" "the committed fixture (uppercase)"
gate_rejects "not-a-key" "a non-hex root"
gate_rejects "5b94" "a truncated root"

# A non-fixture root that does not sign the bundled envelope must be
# rejected: otherwise released binaries fail verification of their own
# bundled fallback (RootMismatch) at startup.
write_envelope "$other_key"
if env ENCLAVA_PLATFORM_RELEASE_ENVELOPE="$GATE_TMP/envelope.json" \
  ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="$prod_key" "$ROOT_GATE" \
  >/tmp/platform-release-root-gate.out 2>/tmp/platform-release-root-gate.err; then
  fail "root gate must reject a root that does not match the bundled envelope signing_pubkey"
fi
grep -Fq -- "ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON together" /tmp/platform-release-root-gate.err \
  || fail "root gate mismatch error must explain the two-secret rotation requirement"

# A matching root/envelope pair passes.
write_envelope "$prod_key"
env ENCLAVA_PLATFORM_RELEASE_ENVELOPE="$GATE_TMP/envelope.json" \
  ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="$prod_key" "$ROOT_GATE" \
  || fail "root gate must accept a non-fixture root matching the bundled envelope"
env ENCLAVA_PLATFORM_RELEASE_ENVELOPE="$GATE_TMP/envelope.json" \
  ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="$(echo "$prod_key" | tr 'a-f' 'A-F')" "$ROOT_GATE" \
  || fail "root gate must accept an uppercase root matching the bundled envelope"

# --allow-dev-fixture (debug/PR builds) only tolerates the fixture while the
# bundled envelope is still fixture-signed.
write_envelope "5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd"
env ENCLAVA_PLATFORM_RELEASE_ENVELOPE="$GATE_TMP/envelope.json" \
  ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd" \
  "$ROOT_GATE" --allow-dev-fixture \
  || fail "root gate must allow the dev fixture for debug builds while the envelope is fixture-signed"
write_envelope "$other_key"
if env ENCLAVA_PLATFORM_RELEASE_ENVELOPE="$GATE_TMP/envelope.json" \
  ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd" \
  "$ROOT_GATE" --allow-dev-fixture \
  >/tmp/platform-release-root-gate.out 2>/tmp/platform-release-root-gate.err; then
  fail "root gate --allow-dev-fixture must still reject a fixture root once the envelope is rotated"
fi

if grep -Fq "id-token: write" <<<"$validate_block" \
  || grep -Fq "packages: write" <<<"$validate_block"; then
  fail "pull-request validation must remain read-only"
fi
grep -Fq "id-token: write" <<<"$publish_block" \
  && grep -Fq "packages: write" <<<"$publish_block" \
  || fail "publisher must request package and keyless-signing permissions"

assert_order "- name: Materialize production platform-release envelope" "- name: Require platform-release root"
assert_order "- name: Require platform-release root" "- name: Build and push"
assert_order "- name: Build and push" "- name: Render digest-pinned release artifact"
assert_order "- name: Render digest-pinned release artifact" "- name: Install cosign"
assert_order "- name: Install cosign" "- name: Sign pushed digest"
assert_order "- name: Sign pushed digest" "- name: Verify signed digest"
assert_order "- name: Verify signed digest" "- name: Upload release manifest artifact"

echo "CAP API image workflow tests passed"
