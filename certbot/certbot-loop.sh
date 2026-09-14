#!/bin/sh
# Obtains and renews the Let's Encrypt certificate for DD_DOMAIN (compose.tls.yaml).
# HTTP-01 challenge via webroot: certbot writes the token into the shared volume and
# nginx serves it on :80, so DD_DOMAIN must resolve to this host and port 80 must be
# reachable from the internet.
#
# certbot keeps live/ and archive/ root-only (0700); nginx runs as uid 1001 / gid 0,
# so the chain + key are published as one gid-0-readable file it can load.
set -u
: "${DD_DOMAIN:?set DD_DOMAIN in .env}"

live="/etc/letsencrypt/live/$DD_DOMAIN"
out=/etc/letsencrypt/nginx

set --
[ "${LETSENCRYPT_STAGING:-false}" = true ] && set -- "$@" --staging
if [ -n "${LETSENCRYPT_EMAIL:-}" ]; then
  set -- "$@" --email "$LETSENCRYPT_EMAIL" --no-eff-email
else
  set -- "$@" --register-unsafely-without-email
fi

publish() {
  [ -s "$live/fullchain.pem" ] || return 0
  mkdir -p "$out"
  chmod 0750 "$out"
  cat "$live/fullchain.pem" "$live/privkey.pem" > "$out/.bundle.tmp"
  chmod 0640 "$out/.bundle.tmp"
  mv "$out/.bundle.tmp" "$out/bundle.pem"   # atomic: nginx never sees a half-written file
}

sleep 15   # give nginx time to start answering on :80
while :; do
  # --keep-until-expiring: no-op until the cert is within 30 days of expiry, so this
  # single command both issues the first certificate and renews it.
  if certbot certonly --webroot -w /var/www/acme -d "$DD_DOMAIN" \
       --agree-tos --non-interactive --keep-until-expiring "$@"; then
    publish
    delay=43200   # 12 h
  else
    # Let's Encrypt allows 5 failed validations per hostname per hour; stay well below.
    echo "certbot: request for $DD_DOMAIN failed, retrying in 30 min" >&2
    delay=1800
  fi
  sleep "$delay"
done
