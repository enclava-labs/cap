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

# Both jobs must install into an isolated interpreter and carry its PATH
# into later steps; pip against Ubuntu's managed Python fails with PEP 668.
for block in "$validate_block" "$publish_block"; do
  for required in \
    'python3 -m venv "$RUNNER_TEMP/api-image-venv"' \
    '"$RUNNER_TEMP/api-image-venv/bin/python3" -m pip install --disable-pip-version-check --quiet "pyyaml==6.0.2"' \
    'printf '\''%s\n'\'' "$RUNNER_TEMP/api-image-venv/bin" >> "$GITHUB_PATH"'; do
    grep -Fq -- "$required" <<< "$block" \
      || fail "each job must provision the guard virtual environment: $required"
  done
done

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

# No template interpolation may appear inside a jobs.*.steps[*].run value
# (#226): values influenced by ref content or dispatch inputs must reach the
# shell only through an env: binding (runner-set, never shell-parsed). The
# workflow is parsed with a real YAML parser (PyYAML) and every
# jobs.*.steps[*].run value is checked as the parser resolves it, so the
# explicit-key mapping form (? run), quoted keys ("run"), flow collections
# ({ run: ... }), the - run: shorthand, block scalars (| and >), multi-line
# plain scalars, and aliases/merge keys that launder an interpolated scalar
# into run: are all covered by construction - there is no line/regex scanner
# left to evade. Step-level run: values are checked, and so is
# defaults.run.shell at both workflow and job scope: it is a command
# template for every step, so interpolations in it are flagged the same
# way. A `run` key anywhere else (job env:, strategy.matrix:, action with:
# inputs) is data, not shell, and an ampersand in a plain scalar is
# just text. Invalid YAML fails closed: an unparsable workflow is rejected,
# never silently skipped. Both CI jobs install pinned PyYAML in a virtual
# environment and put its python3 on PATH; if it is missing the guard exits nonzero so
# CI fails loud instead of letting the workflow through unscanned.
scan_workflow() {
  python3 - "$1" "$2" <<'PYGUARD'
import sys

mode, path = sys.argv[1], sys.argv[2]
try:
    import yaml
except ImportError:
    sys.stderr.write(
        "error: the run-injection guard requires python3 with PyYAML"
        " (python3 -c 'import yaml') to parse the workflow;"
        " refusing to let the workflow through unscanned\n"
    )
    sys.exit(3)

from yaml.nodes import MappingNode, ScalarNode, SequenceNode

findings = []
seen_notes = set()


def note(node, msg):
    if isinstance(node, int):
        line = node
    else:
        line = node.start_mark.line + 1
    key = (line, msg)
    if key not in seen_notes:
        seen_notes.add(key)
        findings.append("%d: %s" % (line, msg))


try:
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    root = yaml.compose(text, Loader=yaml.SafeLoader)
except OSError as exc:
    sys.stderr.write("error: cannot read %s: %s\n" % (path, exc))
    sys.exit(3)
except yaml.YAMLError as exc:
    mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
    detail = str(exc).splitlines()
    reason = detail[0] if detail else exc.__class__.__name__
    note(mark.line + 1 if mark else 1, "invalid YAML, failing closed: %s" % reason)
    root = None

if root is None and not findings:
    note(1, "empty workflow document, failing closed")


def mapping_entries(node):
    # (key, value) pairs of a mapping, recursing through YAML merge keys
    # (<<) so an anchored template cannot hide a run:/steps: entry from
    # the walk.
    if not isinstance(node, MappingNode):
        return
    for key, val in node.value:
        if getattr(key, "tag", "") == "tag:yaml.org,2002:merge":
            sources = val.value if isinstance(val, SequenceNode) else [val]
            for source in sources:
                for pair in mapping_entries(source):
                    yield pair
            continue
        yield key, val


def check_run_value(val):
    if isinstance(val, ScalarNode):
        if "${{" in val.value:
            note(val, "run value interpolates ${{ ... }} directly;"
                      " pass the value through an env: binding instead")
    else:
        note(val, "run value must be a scalar string;"
                  " a %s cannot be a run command" % type(val).__name__)


def check_step_mapping(item, job):
    for key, val in mapping_entries(item):
        if not isinstance(key, ScalarNode):
            continue
        if key.value == "run":
            check_run_value(val)
        elif key.value == "parallel":
            # GitHub parallel step groups nest executable steps under the
            # group item's parallel: key; the invariant applies to each.
            check_steps(val, job)
        elif key.value == "shell":
            # A custom step shell is a command template GitHub splices the
            # run script into ({0}); interpolation here executes directly,
            # exactly like interpolation in the run value itself.
            if isinstance(val, ScalarNode) and "${{" in val.value:
                note(val, "step shell template interpolates ${{ ... }} directly;"
                          " pass the value through an env: binding instead")


def check_steps(node, job):
    if not isinstance(node, SequenceNode):
        note(node, "job '%s': steps must be a sequence" % job)
        return
    for item in node.value:
        if not isinstance(item, MappingNode):
            note(item, "job '%s': each step must be a mapping" % job)
            continue
        check_step_mapping(item, job)


def check_defaults_run_shell(node, owner):
    # defaults.run.shell — top-level or jobs.<id> — is a command template
    # GitHub splices every run script into ({0}); interpolation there
    # executes directly in every step of the job (or the whole workflow),
    # exactly like step-level shell (Codex, #236).
    if not isinstance(node, MappingNode):
        return
    for key, val in mapping_entries(node):
        if not (isinstance(key, ScalarNode) and key.value == "run"):
            continue
        if not isinstance(val, MappingNode):
            continue
        for run_key, shell in mapping_entries(val):
            if (isinstance(run_key, ScalarNode) and run_key.value == "shell"
                    and isinstance(shell, ScalarNode) and "${{" in shell.value):
                note(shell, "%s defaults.run.shell template interpolates"
                            " ${{ ... }} directly; pass the value through"
                            " an env: binding instead" % owner)


def check_workflow_runs(root):
    if not isinstance(root, MappingNode):
        note(root, "workflow root must be a mapping")
        return
    found_jobs = False
    for key, val in mapping_entries(root):
        if not isinstance(key, ScalarNode):
            continue
        if key.value == "defaults":
            check_defaults_run_shell(val, "workflow-level")
            continue
        if key.value != "jobs":
            continue
        found_jobs = True
        if not isinstance(val, MappingNode):
            note(val, "jobs must be a mapping")
            continue
        for job_key, job in mapping_entries(val):
            name = job_key.value if isinstance(job_key, ScalarNode) else "<non-scalar>"
            if not isinstance(job, MappingNode):
                note(job, "job '%s' must be a mapping" % name)
                continue
            for step_key, steps in mapping_entries(job):
                if isinstance(step_key, ScalarNode) and step_key.value == "steps":
                    check_steps(steps, name)
                elif (isinstance(step_key, ScalarNode)
                        and step_key.value == "defaults"):
                    check_defaults_run_shell(steps, "job '%s'" % name)
    if not found_jobs:
        note(root, "workflow has no jobs mapping")


def check_anchors(text):
    # GitHub Actions honors YAML anchors/aliases, and an aliased scalar is
    # resolved before the shell ever sees the text. The resolved run values
    # are checked in run mode, but anchors stay banned outright: the parser
    # event stream reports every anchor/alias token with its position, so
    # any use anywhere in the document is flagged without text matching
    # (which means & in plain scalars, comments, and quoted strings cannot
    # false-positive, and shell globs/operators in run bodies never match).
    from yaml.events import AliasEvent

    try:
        events = yaml.parse(text, Loader=yaml.SafeLoader)
        for event in events:
            anchor = getattr(event, "anchor", None)
            if anchor is None:
                continue
            if isinstance(event, AliasEvent):
                note(event, "YAML alias *%s resolves before the shell sees"
                            " the text; write the value out explicitly"
                            " instead" % anchor)
            else:
                note(event, "YAML anchor &%s defined; aliases resolve before"
                            " the shell sees the text, so write the value"
                            " out explicitly instead" % anchor)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
        reason = str(exc).splitlines()
        note(mark.line + 1 if mark else 1,
             "invalid YAML, failing closed: %s"
             % (reason[0] if reason else exc.__class__.__name__))


if root is not None:
    if mode == "run":
        check_workflow_runs(root)
    elif mode == "anchors":
        check_anchors(text)
    else:
        sys.stderr.write("error: unknown guard mode %r\n" % mode)
        sys.exit(3)

for line in findings:
    print(line)
PYGUARD
}
scan_run_injections() { scan_workflow run "$1"; }
scan_anchor_tokens() { scan_workflow anchors "$1"; }

run_body_injections="$(scan_run_injections "$WORKFLOW")" \
  || fail "run-injection guard could not run: python3 with PyYAML is required"
[[ -z "$run_body_injections" ]] || {
  echo "$run_body_injections" >&2
  fail "workflow interpolates \${{ ... }} directly inside a run: block; pass the value through an env: binding instead"
}
anchor_tokens="$(scan_anchor_tokens "$WORKFLOW")" \
  || fail "anchor/alias guard could not run: python3 with PyYAML is required"
[[ -z "$anchor_tokens" ]] || {
  echo "$anchor_tokens" >&2
  fail "workflow must not use YAML anchors or aliases; an anchored scalar could carry \${{ ... }} past the run-value check (write the env: binding out explicitly instead)"
}

# Self-tests: the guard parses real YAML, so fixtures are full workflow
# documents. Every smuggling shape the guard claims to cover must be flagged,
# and every safe shape must stay clean, so the coverage claim cannot silently
# regress.
guard_tmp="$(mktemp -d)"
guard_case() { printf '%s\n' "$2" >"$guard_tmp/$1.yml"; }
guard_steps_case() {
  printf 'jobs:\n  build:\n    steps:\n%s\n' "$2" >"$guard_tmp/$1.yml"
}
guard_must_flag_run() {
  [[ -n "$(scan_run_injections "$guard_tmp/$1.yml")" ]] \
    || fail "run-injection guard self-test ($1): must be flagged"
}
guard_must_flag_anchors() {
  [[ -n "$(scan_anchor_tokens "$guard_tmp/$1.yml")" ]] \
    || fail "run-injection guard self-test ($1): anchor/alias use must be flagged"
}
guard_must_be_clean() {
  local out
  out="$(scan_run_injections "$guard_tmp/$1.yml")" \
    || fail "run-injection guard self-test ($1): guard failed to run"
  [[ -z "$out" ]] || fail "run-injection guard self-test ($1): must not be flagged: $out"
  out="$(scan_anchor_tokens "$guard_tmp/$1.yml")" \
    || fail "run-injection guard self-test ($1): guard failed to run"
  [[ -z "$out" ]] || fail "run-injection guard self-test ($1): must not be anchor-flagged: $out"
}

# The guard itself must run (python3 + PyYAML present) before anything else.
guard_case canary 'jobs:
  build:
    steps:
      - run: echo ok
'
scan_run_injections "$guard_tmp/canary.yml" >/dev/null \
  || fail "run-injection guard could not run: python3 with PyYAML is required"
guard_must_be_clean canary

# Interpolation in a run: value must be flagged in every YAML shape.

guard_steps_case inline '      - run: echo "${{ github.ref }}"
'
guard_must_flag_run inline
guard_steps_case folded '      - run: >
          echo "${{ github.ref }}"
'
guard_must_flag_run folded
guard_steps_case continuation '      - run: echo start
          and "${{ github.ref }}"
'
guard_must_flag_run continuation
guard_steps_case quoted_run '      - "run": echo "${{ github.ref }}"
'
guard_must_flag_run quoted_run
# Explicit-key mapping form (? run / : value): a real parser resolves it to
# the same step mapping a line scanner can miss (Codex thread PRRT_kwDOSHSH5s6sODl2).
guard_steps_case explicit_key '      - ? run
        : echo "${{ github.ref }}"
'
guard_must_flag_run explicit_key
guard_case flow_run 'jobs: {build: {steps: [{run: "echo ${{ github.ref }}"}]}}
'
guard_must_flag_run flow_run
guard_steps_case flow_key_order '      - {name: deploy, run: "echo ${{ github.ref }}"}
'
guard_must_flag_run flow_key_order

# Aliases and merge keys launder an interpolated scalar into run:; the
# parser resolves them, so the run check flags the resolved value and the
# anchor check flags the anchor itself.

guard_steps_case aliased '      - env:
          SCRIPT: &unsafe_script echo "${{ github.ref }}"
        run: *unsafe_script
'
guard_must_flag_run aliased
guard_must_flag_anchors aliased
guard_case merge_template 'templates:
  risky: &risky_step
    run: echo "${{ github.ref }}"
jobs:
  build:
    steps:
      - <<: *risky_step
        name: merged from template
'
guard_must_flag_run merge_template
guard_must_flag_anchors merge_template
guard_case anchored_whole_step 'templates:
  step: &whole_step
    run: echo "${{ github.ref }}"
jobs:
  build:
    steps:
      - *whole_step
'
guard_must_flag_run anchored_whole_step
guard_must_flag_anchors anchored_whole_step
guard_steps_case numeric_alias '      - env:
          SCRIPT: &1 echo "${{ github.ref }}"
        run: *1
'
guard_must_flag_anchors numeric_alias

# Malformed or unparsable workflow YAML fails closed, never silently clean.

guard_steps_case non_scalar_run '      - run: [echo, "${{ github.ref }}"]
'
guard_must_flag_run non_scalar_run
guard_steps_case scalar_step '      - just a string
'
guard_must_flag_run scalar_step
guard_case no_jobs 'name: not a workflow
'
guard_must_flag_run no_jobs
guard_case unclosed_flow 'jobs: {build: {steps: [{run: "echo ${{ github.ref }}"
'
guard_must_flag_run unclosed_flow
guard_must_flag_anchors unclosed_flow
guard_steps_case bare_alias_run '      - run: *payload
'
guard_must_flag_run bare_alias_run
guard_steps_case punct_anchor '      - env:
          SCRIPT: &-risky echo "${{ github.ref }}"
        run: *-risky
'
guard_must_flag_run punct_anchor
guard_must_flag_anchors punct_anchor

# A custom step shell is a command template ({0} receives the run script):
# interpolation there executes directly and must be flagged (Codex, #236).
guard_steps_case shell_template '      - run: echo ok
        shell: bash -c '"'"'echo "${{ github.head_ref }}"; bash {0}'"'"'
'
guard_must_flag_run shell_template
guard_steps_case shell_plain '      - run: echo ok
        shell: bash
'
guard_must_be_clean shell_plain

# defaults.run.shell at either scope is a command template for every step
# in the job (or workflow); interpolation there must be flagged, and a
# plain default shell must stay clean (Codex, #236).
guard_case job_defaults_shell 'jobs:
  build:
    defaults:
      run:
        shell: bash -c '"'"'echo "${{ github.head_ref }}"; bash {0}'"'"'
    steps:
      - run: echo ok
'
guard_must_flag_run job_defaults_shell
guard_case top_defaults_shell 'defaults:
  run:
    shell: bash -c '"'"'echo "${{ github.head_ref }}"; bash {0}'"'"'
jobs:
  build:
    steps:
      - run: echo ok
'
guard_must_flag_run top_defaults_shell
guard_case defaults_shell_plain 'defaults:
  run:
    shell: bash
jobs:
  build:
    steps:
      - run: echo ok
'
guard_must_be_clean defaults_shell_plain

# GitHub parallel step groups nest executable steps under parallel:; each
# nested step is checked like a top-level one (Codex, #236).
guard_steps_case parallel_group '      - parallel:
          - run: echo "${{ github.head_ref }}"
'
guard_must_flag_run parallel_group
guard_steps_case parallel_group_safe '      - parallel:
          - run: echo "$PUSHED_REF"
            env:
              PUSHED_REF: ${{ github.ref }}
'
guard_must_be_clean parallel_group_safe

# Safe shapes must stay clean.

guard_steps_case env_bound '      - name: safe
        env:
          PUSHED_REF: ${{ github.ref }}
        run: |
          echo "$PUSHED_REF"
'
guard_must_be_clean env_bound
guard_steps_case seq_marker_run_env '      - run: echo "$PUSHED_REF"
        env:
          PUSHED_REF: ${{ github.ref }}
'
guard_must_be_clean seq_marker_run_env
# A `run` key that is not a step command (action input) is data, not shell
# (Codex thread PRRT_kwDOSHSH5s6ODmD).
guard_steps_case with_run_input '      - uses: example/action@0000000000000000000000000000000000000000
        with:
          run: deploy ${{ github.ref }}
      - run: echo ok
'
guard_must_be_clean with_run_input
# A `run` key in job env: is an environment variable name, not a command
# (Codex thread PRRT_kwDOSHSH5s6ODmD).
guard_case job_env_run 'jobs:
  build:
    env:
      run: not-a-command
    steps:
      - run: echo ok
'
guard_must_be_clean job_env_run
guard_case matrix_run 'jobs:
  build:
    strategy:
      matrix:
        run: [one, two]
    steps:
      - run: echo ok
'
guard_must_be_clean matrix_run
# Flow-looking JSON inside a with: block scalar is action input data, not a
# flow collection and not a run command (Codex thread PRRT_kwDOSHSH5s6sODmA).
guard_steps_case with_metadata_json '      - uses: example/action@0000000000000000000000000000000000000000
        with:
          metadata: |
            {"flow": "{ run: \"echo ${{ github.ref }}\" }"}
      - run: echo ok
'
guard_must_be_clean with_metadata_json
guard_case defaults_run 'jobs:
  build:
    defaults:
      run:
        shell: bash
    steps:
      - run: echo ok
'
guard_must_be_clean defaults_run
guard_steps_case flow_env_safe '      - {run: "echo \"$PUSHED_REF\"", env: {PUSHED_REF: "${{ github.ref }}"}}
'
guard_must_be_clean flow_env_safe

# Text that merely looks like anchor syntax must not trip the anchor ban.

# An ampersand in a plain scalar is literal text, not an anchor (Codex
# thread PRRT_kwDOSHSH5s6sODl7).
guard_case plain_amp 'name: Research &security release
jobs:
  build:
    steps:
      - name: R&D &ship it
        run: echo ok
'
guard_must_be_clean plain_amp
guard_steps_case shell_glob '      - run: ls -la *.txt
'
guard_must_be_clean shell_glob
guard_steps_case shell_operators '      - run: make -j2 && ./test.sh || true
'
guard_must_be_clean shell_operators
guard_steps_case anchor_in_comment '      - run: echo ok
# Support R&D &security release naming
'
guard_must_be_clean anchor_in_comment
guard_case anchor_in_quoted 'name: "R&D &friends"
jobs:
  build:
    steps:
      - run: echo ok
'
guard_must_be_clean anchor_in_quoted
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
  "--example platform-release -- verify-baseline" \
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

python3 - "$WORKFLOW" <<'PYTAGS'
import os
import subprocess
import sys
import yaml

steps = {
    step.get("name"): step
    for step in yaml.safe_load(open(sys.argv[1]))["jobs"]["publish"]["steps"]
}
cases = [
    ("Validate manual image tag", "VERSION_TAG", "", "manual-" + "a" * 120, True),
    ("Validate manual image tag", "VERSION_TAG", "preprod-", "manual-" + "a" * 113, True),
    ("Validate manual image tag", "VERSION_TAG", "preprod-", "manual-" + "a" * 114, False),
    ("Validate pushed tag name", "PUSHED_REF", "", "refs/tags/v" + "a" * 127, True),
    ("Validate pushed tag name", "PUSHED_REF", "", "refs/tags/v" + "a" * 128, False),
    ("Validate pushed tag name", "PUSHED_REF", "preprod-", "refs/tags/v" + "a" * 119, True),
    ("Validate pushed tag name", "PUSHED_REF", "preprod-", "refs/tags/v" + "a" * 120, False),
]
for name, variable, prefix, value, accepted in cases:
    result = subprocess.run(
        ["bash", "-e", "-c", steps[name]["run"]],
        env={**os.environ, variable: value, "IMAGE_TAG_PREFIX": prefix},
        capture_output=True,
        text=True,
    )
    if (result.returncode == 0) != accepted:
        raise SystemExit(f"{name}: wrong acceptance for prefix {prefix!r}, value length {len(value)}")
PYTAGS

echo "CAP API image workflow tests passed"
