#!/usr/bin/env bash
# Drift checker for
# crates/enclava-cli/tests/fixtures/template_deployment_status_vocabulary.json
# (cap#402).
#
# The fixture pins the template-deployment status vocabulary shared by
# enclava-labs/cap (CAP deploy statuses, relayed as reconciled_status) and
# enclava-labs/enclava-paas (stored/projection/folded statuses). The contract
# test `deployment_status_vocabulary_stays_classified` fails whenever the
# fixture and the CLI classifier sets disagree; THIS script fails whenever the
# owning servers' sources grew a status the fixture does not pin.
#
# Usage:
#   scripts/gen-template-deployment-status-vocabulary.sh
#
# This is a check-only script: the fixture is updated by hand when it fails,
# and the script verifies both sides stay in step. It extracts from these
# exact sites — extend the extraction when a new status surface appears:
#   cap:  crates/enclava-api/src/models.rs::DeployStatus variants
#   paas: server/src/hosted_status.rs::normalize_observed_status input arms
#         server/src/hosted_operations.rs::deployment_db_status input arms
# The PaaS half is checked only when a checkout exists at ../enclava-paas
# (cap CI does not vendor enclava-paas, so a PaaS-side status addition is
# caught when this script runs with that checkout present — e.g. by a CI job
# that checks out enclava-paas, or the follow-up ledger sweep).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
fixture="$root/crates/enclava-cli/tests/fixtures/template_deployment_status_vocabulary.json"
paas_root="${ENCLAVA_PAAS_CHECKOUT:-$root/../enclava-paas}"

[ -f "$fixture" ] || { echo "missing fixture: $fixture"; exit 1; }

fixture_statuses() {
    grep -o '"status": "[a-z_]*"' "$fixture" | sed 's/.*"status": "\([a-z_]*\)"/\1/' | sort -u
}

fail=0

check_origin() {
    local owner="$1"; shift
    # Fail closed on a broken extraction: silently checking zero statuses is
    # exactly the drift this script exists to catch.
    if [ "$#" -eq 0 ]; then
        echo "DRIFT [$owner]: extracted zero statuses — the extraction is broken or the source renamed"
        exit 1
    fi
    local want
    for want in "$@"; do
        if ! fixture_statuses | grep -qx "$want"; then
            echo "DRIFT [$owner]: status '$want' is not pinned in $(basename "$fixture")"
            fail=1
        fi
    done
}

# --- cap half: crates/enclava-api/src/models.rs::DeployStatus -------------
# Serde renames: lowercase, RolledBack -> rolled_back.
models="$root/crates/enclava-api/src/models.rs"
[ -f "$models" ] || { echo "missing $models"; exit 1; }
mapfile -t cap_statuses < <(
    sed -n '/pub enum DeployStatus {/,/^}/p' "$models" \
        | grep -oE '^\s+(#\[[^]]*\]\s*)*[A-Z][A-Za-z]+,?' \
        | grep -oE '[A-Z][A-Za-z]+' \
        | sed -E 's/([a-z])([A-Z])/\1_\2/' | tr '[:upper:]' '[:lower:]' | sort -u
)
check_origin "cap DeployStatus" "${cap_statuses[@]}"

# --- paas half (optional): stored + folded vocabularies ------------------
if [ -d "$paas_root/server/src" ]; then
    hosted_status="$paas_root/server/src/hosted_status.rs"
    hosted_operations="$paas_root/server/src/hosted_operations.rs"
    for source in "$hosted_status" "$hosted_operations"; do
        [ -f "$source" ] || { echo "missing $source"; exit 1; }
    done
    mapfile -t paas_statuses < <(
        {
            # normalize_observed_status + deployment_db_status input arms
            sed -n '/fn normalize_observed_status/,/^}/p' "$hosted_status"
            sed -n '/fn deployment_db_status/,/^}/p' "$hosted_operations"
        } | grep -oE '"[a-z_]+"' | tr -d '"' | sort -u
    )
    check_origin "enclava-paas observed/stored statuses" "${paas_statuses[@]}"
else
    echo "note: no enclava-paas checkout at $paas_root — skipping the PaaS half"
fi

if [ "$fail" -ne 0 ]; then
    echo "regenerate by adding the statuses above to $fixture with their class"
    echo "(in_flight/terminal/folded) and origin, then update"
    echo "crates/enclava-cli/src/template_deploy_retry.rs::IN_FLIGHT_STATUSES /"
    echo "TERMINAL_STATUSES until deployment_status_vocabulary_stays_classified passes."
    exit 1
fi
echo "ok: status vocabulary pinned ($(fixture_statuses | wc -l) statuses)"
