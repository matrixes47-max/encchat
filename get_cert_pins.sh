#!/bin/bash
# encchat — Certificate Pin Hash Generator
# გაუშვი ეს სკრიპტი, შემდეგ მიღებული hash-ები ჩასვი network_security_config.xml-ში

get_pin() {
  local host=$1
  echo "📌 $host"
  echo | openssl s_client -connect "$host:443" -servername "$host" 2>/dev/null \
    | openssl x509 -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | base64
}

echo "=== encchat Certificate Pins ==="
echo ""
PROXY_PIN=$(get_pin "geo.encchat.workers.dev")
echo "Proxy pin: $PROXY_PIN"
echo ""
BACKEND_PIN=$(get_pin "encchat-q10a.onrender.com")
echo "Backend pin: $BACKEND_PIN"
echo ""
echo "=== network_security_config.xml-ში ჩასვი ==="
echo ""
cat << XMLEOF
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">geo.encchat.workers.dev</domain>
        <domain includeSubdomains="true">encchat-q10a.onrender.com</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">$PROXY_PIN</pin>
            <pin digest="SHA-256">$BACKEND_PIN</pin>
        </pin-set>
    </domain-config>
</network-security-config>
XMLEOF
