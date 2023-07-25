#!/usr/bin/env bash
# ref: https://gist.github.com/briceburg/0d6589714862004609daf77f4fc4aac9
# 
# usage: JWT_SECRET="silly" mk-jwt-token 
# @WARN: modify the payload and header to your needs.
#  
main(){
  set -eo pipefail

  [ -n "$JWT_SECRET" ] || die "JWT_SECRET environment variable is not set."

  # number of seconds to expire token. default 1h
  expire_seconds="${JWT_EXPIRATION_IN_SECONDS:-3600}"

  # pass JWT_SECRET_BASE64_ENCODED as true if secret is base64 encoded
  ${JWT_SECRET_BASE64_ENCODED:-false} && \
    JWT_SECRET=$(printf %s "$JWT_SECRET" | base64 --decode)

  header='{
    "alg": "HS256",
  	"typ": "JWT"
  }'

  payload="{
    \"iss\": \"eudi.issuer.org\",
    \"iat\": $(date +%s),
    \"exp\": $(($(date +%s)+expire_seconds)),
    \"nbf\": $(($(date +%s)-1))
  }"
  claims=$(cat $1)
  payload=$(echo $payload $claims | jq -s add )

  header_base64=$(printf %s "$header" | base64_urlencode)
  payload_base64=$(printf %s "$payload" | base64_urlencode)
  signed_content="${header_base64}.${payload_base64}"
  signature=$(printf %s "$signed_content" | openssl dgst -binary -sha256 -hmac "$JWT_SECRET" | base64_urlencode)

  # log "generated JWT token. expires in $expire_seconds seconds -->\\n\\n"
  printf '%s' "${signed_content}.${signature}"
}

base64_urlencode() { openssl enc -base64 -A | tr '+/' '-_' | tr -d '='; }
readonly __entry=$(basename "$0")
log(){ echo -e "$__entry: $*" >&2; }
die(){ log "$*"; exit 1; }
main "$@"
