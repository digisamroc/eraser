#!/usr/bin/env bash
# Run govulncheck and fail on any reachable vulnerability not listed below.
#
# Accepted (each entry needs a reason and a plan to remove it):
#   GO-2025-3884  gorilla/csrf TrustedOrigins validation; no upstream fix.
#                 Removed in Phase 5 by switching to net/http CrossOriginProtection.
set -euo pipefail

ALLOWED=(GO-2025-3884)

out=$(govulncheck -format json ./...)

found=$(jq -r 'select(.finding != null and .finding.trace[0].function != null) | .finding.osv' <<<"$out" | sort -u)

status=0
for id in $found; do
  if [[ " ${ALLOWED[*]} " == *" $id "* ]]; then
    echo "allowed: $id"
  else
    echo "VULNERABLE: $id (https://pkg.go.dev/vuln/$id)"
    status=1
  fi
done

if [[ $status -eq 0 ]]; then
  echo "govulncheck: no unaccepted reachable vulnerabilities"
fi
exit $status
