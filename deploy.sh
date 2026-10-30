#!/usr/bin/env bash
# Portable deploy for the GRC Security Intelligence bundle.
# Picks the first available SQL warehouse in the current workspace and passes its ID
# to the bundle (--var warehouse_id skips the warehouse_name lookup in databricks.yml,
# which would otherwise fail when the workspace has no "Serverless Starter Warehouse").
#
# Usage:
#   bash deploy.sh [target] [catalog]
#     target  - bundle target (default: free)
#     catalog - UC catalog for the GRC schemas (default: none = bundle default `workspace`;
#               pass e.g. `main` on non-Free-Edition workspaces)
#
# Requires: databricks CLI (authenticated) and jq.
set -euo pipefail
TARGET="${1:-free}"
CATALOG="${2:-}"

# 1) Pick the first SQL warehouse available in this workspace.
WH_ID="$(databricks warehouses list --output JSON | jq -r '[.[] | select(.id != null)][0].id // empty')"

# 2) If the workspace has no warehouse at all, create a small serverless one.
if [ -z "${WH_ID}" ]; then
  echo "No SQL warehouse found - creating 'GRC Starter Warehouse' (X-Small, serverless)..."
  WH_ID="$(databricks warehouses create \
      --name "GRC Starter Warehouse" \
      --cluster-size "X-Small" \
      --warehouse-type "SERVERLESS" \
      --auto-stop-minutes 10 \
      --output JSON | jq -r '.id')"
fi

echo "Using SQL warehouse: ${WH_ID}"

# 3) Build the variable overrides. An explicit --var warehouse_id skips the name lookup.
VAR_ARGS=(--var "warehouse_id=${WH_ID}")
if [ -n "${CATALOG}" ]; then
  VAR_ARGS+=(--var "catalog=${CATALOG}")
  echo "Using catalog: ${CATALOG}"
fi

# 4) Validate, deploy all resources, then push the app deployment (with env vars).
databricks bundle validate --strict --target "${TARGET}" "${VAR_ARGS[@]}"
databricks bundle deploy  --target "${TARGET}" "${VAR_ARGS[@]}"
databricks bundle run grc_app --target "${TARGET}" "${VAR_ARGS[@]}"

echo "Done. Run the one-time setup job (GRC Security Intelligence - One-time Setup) next."
