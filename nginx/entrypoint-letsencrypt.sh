#!/bin/sh
# Wraps DefectDojo's stock nginx entrypoint to serve HTTPS with the Let's Encrypt
# certificate the certbot service publishes (compose.tls.yaml).
#
#   SRC  cert chain + key, written atomically by certbot/certbot-loop.sh
#   DST  the copy nginx actually serves
set -eu

SRC=/etc/letsencrypt/nginx/bundle.pem
DST=/etc/nginx/ssl/bundle.pem
CONF=/etc/nginx/nginx_TLS.conf

umask 0027
if [ -s "$SRC" ]; then
  cp "$SRC" "$DST"
else
  # No certificate yet (first boot): a short-lived self-signed placeholder lets nginx
  # start, so it can answer the ACME HTTP-01 challenge on :80.
  echo "letsencrypt: no certificate yet, serving a self-signed placeholder for ${DD_DOMAIN}"
  tmp=$(mktemp -d)
  openssl req -x509 -nodes -days 7 -newkey rsa:2048 -subj "/CN=${DD_DOMAIN}" \
    -keyout "$tmp/key" -out "$tmp/crt" 2>/dev/null
  cat "$tmp/crt" "$tmp/key" > "$DST"
  rm -rf "$tmp"
fi
cp /etc/nginx/letsencrypt.conf "$CONF"

# Pick up the first issued certificate and every renewal without a container restart.
(
  while sleep 60; do
    if [ -s "$SRC" ] && ! cmp -s "$SRC" "$DST"; then
      cp "$SRC" "$DST.new" && mv "$DST.new" "$DST"
      if nginx -c "$CONF" -t -q && nginx -c "$CONF" -s reload; then
        echo "letsencrypt: certificate updated, nginx reloaded"
      else
        echo "letsencrypt: new certificate rejected by nginx, still serving the old one" >&2
      fi
    fi
  done
) &

export USE_TLS=true GENERATE_TLS_CERTIFICATE=false
exec /entrypoint-nginx.sh
