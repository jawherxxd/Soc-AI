#!/bin/bash
# ============================================================
#  SCÉNARIO DE DÉMO — SOC Pipeline (v4 - syntaxe corrigée)
#  4 tactiques MITRE + doublons. Unicité par compteur.
# ============================================================

WEBHOOK="http://localhost:8000/alert"
DST="10.10.10.253"

IP_BRUTE="45.148.10.35"
IP_SCAN="89.248.165.42"
IP_WEB="185.220.101.34"
IP_C2="193.32.162.20"

COUNTER=0

send_alert() {
  srcip="$1"; rule_id="$2"; desc="$3"; level="$4"
  tactic="$5"; technique="$6"; tid="$7"; dstport="$8"
  COUNTER=$((COUNTER + 1))
  uniq="demo-${COUNTER}-$$-${RANDOM}"
  ts=$(date -u +%Y-%m-%dT%H:%M:%S)
  sport=$((RANDOM % 60000 + 1024))

  # Construction du JSON dans une variable (plus sûr)
  json=$(cat <<JSON
{
  "id": "${uniq}",
  "timestamp": "${ts}.${COUNTER}Z",
  "agent": {"name": "suricata", "ip": "${DST}"},
  "rule": {"id": ${rule_id}, "description": "${desc}", "level": ${level},
    "groups": ["suricata","ids"],
    "mitre": {"tactic": ["${tactic}"], "technique": ["${technique}"], "id": ["${tid}"]}},
  "data": {"srcip": "${srcip}", "dstip": "${DST}", "srcport": "${sport}", "dstport": "${dstport}", "proto": "tcp"},
  "full_log": "${desc} from ${srcip}"
}
JSON
)

  resp=$(curl -s -X POST "$WEBHOOK" -H "Content-Type: application/json" -d "$json")
  stored=$(echo "$resp" | grep -o '"stored":[a-z]*' | cut -d: -f2)
  echo "  [${tactic}] ${srcip} -> stored=${stored}"
}

echo "=========================================================="
echo "   DEMO SOC — 4 tactiques MITRE"
echo "=========================================================="
echo ""

echo "VAGUE 1 : Force brute SSH (Credential Access) — 15 alertes"
for i in $(seq 1 15); do
  send_alert "$IP_BRUTE" 5710 "SSH brute force authentication failure" 10 "Credential Access" "Brute Force" "T1110" 22
  sleep 0.2
done
echo ""

echo "VAGUE 2 : Balayage de ports (Discovery) — 12 alertes"
for port in 21 22 23 25 80 135 139 443 445 3306 3389 8080; do
  send_alert "$IP_SCAN" 9000001 "Nmap SYN port scan detected" 10 "Discovery" "Network Service Scanning" "T1046" "$port"
  sleep 0.2
done
echo ""

echo "VAGUE 3 : Exploitation web (Initial Access) — 8 alertes"
for i in $(seq 1 8); do
  send_alert "$IP_WEB" 31151 "Web attack SQL injection attempt" 12 "Initial Access" "Exploit Public-Facing Application" "T1190" 443
  sleep 0.2
done
echo ""

echo "VAGUE 4 : Command and Control (C2) — 6 alertes"
for i in $(seq 1 6); do
  send_alert "$IP_C2" 86601 "Outbound connection to known C2 server" 13 "Command and Control" "Application Layer Protocol" "T1071" 8443
  sleep 0.2
done
echo ""

echo "VAGUE 5 : Doublons intentionnels (reduction) — 10 alertes"
dup_json=$(cat <<'JSON'
{
  "id": "duplicate-fixed-id",
  "timestamp": "2026-08-25T10:00:00.000Z",
  "agent": {"name": "suricata", "ip": "10.10.10.253"},
  "rule": {"id": 5710, "description": "SSH brute force authentication failure", "level": 10,
    "groups": ["suricata","ids"],
    "mitre": {"tactic": ["Credential Access"], "technique": ["Brute Force"], "id": ["T1110"]}},
  "data": {"srcip": "45.148.10.35", "dstip": "10.10.10.253", "srcport": "44444", "dstport": "22", "proto": "tcp"},
  "full_log": "SSH duplicate"
}
JSON
)
for i in $(seq 1 10); do
  resp=$(curl -s -X POST "$WEBHOOK" -H "Content-Type: application/json" -d "$dup_json")
  dup=$(echo "$resp" | grep -o '"is_duplicate":[a-z]*' | cut -d: -f2)
  echo "  [DOUBLON] 45.148.10.35 -> is_duplicate=${dup}"
  sleep 0.1
done
echo ""

echo "=========================================================="
echo "   TERMINE : 41 uniques + 10 doublons = 51 envoyees"
echo "   Attendez ~60s puis observez Grafana + UI SOC-AI"
echo "=========================================================="
