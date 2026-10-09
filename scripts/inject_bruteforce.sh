#!/bin/bash
# ============================================================
#  Injection — Communication Command & Control (C2)
#  Un hôte interne compromis contacte un serveur C2 externe
#  Démo ENRICHISSEMENT (IP C2 publique) + CORRÉLATION
#  Tactique MITRE : Command and Control (T1071)
#  À lancer DEPUIS LA VM PIPELINE (10.10.10.251)
# ============================================================

WEBHOOK="http://localhost:8000/alert"
SRC_IP="10.10.10.199"        # hôte interne COMPROMIS (Windows PC)
C2_IP="193.32.162.20"        # serveur C2 externe (IP publique malveillante)

# Plusieurs événements de communication C2 (règles variées -> passent la dédup)
declare -a RULES=(
  "86601|Outbound connection to known C2 server"
  "86610|Suspicious periodic beaconing detected"
  "86615|Connection to known malicious IP (threat intel)"
  "86620|Encrypted C2 channel over non-standard port"
  "86630|Data exfiltration attempt to external host"
)

echo "=========================================================="
echo "  DÉMO C2 — Hôte interne $SRC_IP -> serveur C2 $C2_IP"
echo "  IP C2 PUBLIQUE -> géolocalisation + réputation attendues"
echo "  ${#RULES[@]} alertes -> 1 incident Command and Control"
echo "=========================================================="
echo ""

i=0
for entry in "${RULES[@]}"; do
  i=$((i+1))
  RULE_ID="${entry%%|*}"
  DESC="${entry##*|}"
  WAZUH_ID="$(date +%s).$((RANDOM * 10 + i))"
  TS="$(date -u +%Y-%m-%dT%H:%M:%S)Z"
  SPORT=$((RANDOM % 60000 + 1024))

  # Pour le C2 : la destination est l'IP publique malveillante
  # (c'est elle qui sera enrichie : réputation du serveur C2)
  RESP=$(curl -s -X POST "$WEBHOOK" -H "Content-Type: application/json" -d '{
    "id": "'"$WAZUH_ID"'",
    "timestamp": "'"$TS"'",
    "agent": {"name": "suricata", "ip": "10.10.10.253"},
    "rule": {"id": '"$RULE_ID"', "description": "'"$DESC"'", "level": 12,
      "groups": ["suricata","c2","malware"],
      "mitre": {"tactic": ["Command and Control"], "technique": ["Application Layer Protocol"], "id": ["T1071"]}},
    "data": {"srcip": "'"$C2_IP"'", "dstip": "'"$SRC_IP"'", "srcport": "'"$SPORT"'", "dstport": "8443", "proto": "tcp"}
  }')

  STORED=$(echo "$RESP" | grep -o '"stored":[a-z]*' | cut -d: -f2)
  DUP=$(echo "$RESP" | grep -o '"is_duplicate":[a-z]*' | cut -d: -f2)
  RISK=$(echo "$RESP" | grep -o '"risk_score":[0-9.]*' | cut -d: -f2)
  echo "  Alerte $i (rule $RULE_ID) -> stored=$STORED | dup=$DUP | risk=$RISK"
  sleep 0.5
done

echo ""
echo "=========================================================="
echo "  ${#RULES[@]} alertes C2 envoyées (serveur $C2_IP)"
echo "  -> Attendez ~60s (cycle du moteur)"
echo "  -> Plateforme : 1 incident 'Command and Control' ENRICHI"
echo "     • le serveur C2 externe est géolocalisé et noté (réputation)"
echo "     • ${#RULES[@]} alertes corrélées"
echo "=========================================================="
