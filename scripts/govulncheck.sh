#!/usr/bin/env bash
# Run govulncheck and fail on any reachable vulnerability not listed below.
#
# Accepted (each entry needs a reason and a plan to remove it): none.
set -euo pipefail

ALLOWED=()

out=$(govulncheck -format json ./...)

found=$(jq -r 'select(.finding != null and .finding.trace[0].function != null) | .finding.osv' <<<"$out" | sort -u)

status=0
for id in $found; do
  if [[ " ${ALLOWED[*]-} " == *" $id "* ]]; then # "-": bash 3.2 treats an empty array as unset
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
