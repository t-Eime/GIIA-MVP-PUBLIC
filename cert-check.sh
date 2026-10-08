#!/data/data/com.termux/files/usr/bin/bash
echo "=== ALL CERTIFICATES AUDIT ==="
echo "Date: $(date)"
echo ""

echo "--- 1. SYSTEM TRUST STORE ---"
echo "Location: /system/etc/security/cacerts"
ls /system/etc/security/cacerts 2>&1 | wc -l | xargs echo "System certs:"
ls /system/etc/security/cacerts 2>&1 | head -n 5
echo ""

echo "--- 2. USER-ADDED CERTS (MITM check) ---"
echo "Location: /data/misc/user/0/cacerts-added"
if [ -d /data/misc/user/0/cacerts-added ]; then
  ls /data/misc/user/0/cacerts-added 2>&1
  COUNT=$(ls /data/misc/user/0/cacerts-added 2>/dev/null | wc -l)
  if [ "$COUNT" -gt 0 ]; then
    echo "WARNING: $COUNT user certs installed - possible proxy/MITM"
  else
    echo "Clean: No user certs"
  fi
else
