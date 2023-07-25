# EUDI Verifier Endpoint - Howto id_token request using direct_post

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Example of this scenario:
- Request for id_token
- Submit Wallet Response - Direct Post

## Table of contents

* [verifier to verifier backend, to post request for id_token](#requesting-an-idtoken)
* [wallet to verifier backend, to get request](#getting-the-request-object)
* [wallet to verifier backend, to post wallet response, an idToken](#submit-wallet-response---direct-post)
* [verifier to verifier backend, to get the wallet response](#get-wallet-response---direct-post)

## Requesting an id_token

Sequence diagram interaction:
- ISO(1) prepare request_uri
- OIDVP(2) initiate transaction
- OIDVP(3) return transaction-id & request-id

```bash
curl -X POST -H "Content-type: application/json" -d '{
  "type": "id_token",
  "id_token_type": "subject_signed_id_token",
  "nonce" : "nonce"
}' 'http://localhost:8080/ui/presentations'
```

Successful output looks like:

```json
{
  "presentation_id":"baDc1Sfebu01dbXoGDQjUbMsclddgVed97gdPXqOzY-gRUP-rRfK8wlHXtims2pSZSXHeaH5RMOVyAF1OhdOxQ",
  "client_id":"Verifier",
  "request_uri":"http://localhost:8080/wallet/request.jwt/KFmJhUTjY2HCgXPT91UlYsqREHpLIsQHMykHinQILweiAFuZmVoa-os4ySaAJceYmeQT2LoabepOFLblFGrqew"
}
```

## Getting the request object

Sequence diagram interaction:
- ISO(6) get request object
- ISO(7) JWS Authorisation request object [section B.3.2.1]

Accessing the request_uri:

(legacy curl - before v7.83.0)
```bash
curl "http://localhost:8080/wallet/request.jwt/KFmJhUTjY2HCgXPT91UlYsqREHpLIsQHMykHinQILweiAFuZmVoa-os4ySaAJceYmeQT2LoabepOFLblFGrqew" \
  --include
```
returns:
```txt
HTTP/1.1 200 OK
Content-Type: application/oauth-authz-req+jwt
Content-Length: 1901

eyJraWQiOiIwZDk5OTI4My1kZTM0LTQwMjYtODk5Mi1jYTRlM2EzMzUyODMiLCJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiUlMyNTYifQ.eyJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvd2FsbGV0L2RpcmVjdF9wb3N0Iiwic2NvcGUiOiJvcGVuaWQiLCJjbGllbnRfaWRfc2NoZW1lIjoicHJlLXJlZ2lzdGVyZWQiLCJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJpZF90b2tlbl90eXBlIjoic3ViamVjdF9zaWduZWRfaWRfdG9rZW4iLCJzdGF0ZSI6IktGbUpoVVRqWTJIQ2dYUFQ5MVVsWXNxUkVIcExJc1FITXlrSGluUUlMd2VpQUZ1Wm1Wb2Etb3M0eVNhQUpjZVltZVFUMkxvYWJlcE9GTGJsRkdycWV3IiwiaWF0IjoxNjg5NzcyMzI2LCJub25jZSI6Im5vbmNlIiwiY2xpZW50X2lkIjoiVmVyaWZpZXIiLCJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6IjBkOTk5MjgzLWRlMzQtNDAyNi04OTkyLWNhNGUzYTMzNTI4MyIsImlhdCI6MTY4OTc3MjIzMywibiI6ImtwT3RkemFhdGp2ODZqWE5ETm5OYVVub3Y5ZnpnTzhWUmNkWEQ2U01VWk56U0xwRWo0U2JfQ0pRS0o0X0JaOS05eFRUOWtCbV8xanVKQ3lGem0yZ2llZDlQU3J4VHFCTEpTcGZ2ZHFwOXo4bTJJenlid1ZxRnRBQXhwNHBvUkVPQ2dXYlloXzR3YVIyWmFEZkdMYWNLdlJfNTM3alJLTm0wT2J6NG5iOFFPalUzU0VLR2JXRFpPelVCaFB4MndObTlkNVU3YXFOZGZkM3VfaEg3ZmJFNjZhMHYyV3R2bmR3a05WZE9CaXhZMUY3QzVFQUc4bDF1dU1SVmZuWnZQS3d6dUVoR25MZTNCMkh4UzVXdk1rLTNBbHlaT2RDcDZiUmxiNEoyRGF1Zlp3cGNPek9Gc05VUFRKbHVKd1p5SzdndjNRSk9zVHNmSTNFYVRqdmRuY1VEdyJ9XX0sImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9hbGciOiJSUzI1NiIsImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMTI4Q0JDLUhTMjU2Iiwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbInVybjppZXRmOnBhcmFtczpvYXV0aDpqd2stdGh1bWJwcmludCIsImRpZDpleGFtcGxlIiwiZGlkOmtleSJdLCJpZF90b2tlbl9zaWduZWRfcmVzcG9uc2VfYWxnIjoiUlMyNTYifSwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0In0.CRPSsPMevO5hy-Y5nwKTzgEoiYuvPviOmw4TVCYk402b_6O5szlkRI82e2z6bLdbgH2LB1Xk_OAe57czNXGBkTwiCUcrrPHaJBkTcsHBKDCrdJ8ADc7BhI3aufA2BCrPa_hWNpnJfJQfQ8IszvKgksnjc_8xfUXLJM6dXRsyHlWxS42gTx67FOsUWEAnk2LI5M77pCvnwJUOXnGMAFg4YuWMEwgyuJQw_QrHR5TANcVu3cH8b_PtZfLodd8bpudFHJ_gh8bHY7KgcCGI5fvHun7yrpsYFhd2639N8AlZl_LvUcGnQ2WQB_IE9wZ60Q4LedxMhdvJbLWCZW9SkygkJw
```

(curl v7.83.0 or later)
```bash
curl "http://localhost:8080/wallet/request.jwt/KFmJhUTjY2HCgXPT91UlYsqREHpLIsQHMykHinQILweiAFuZmVoa-os4ySaAJceYmeQT2LoabepOFLblFGrqew" \
  --write-out '\nResponse_code: %{response_code}\nContent-type: %header{Content-Type}' 
```

returns:
```base64
eyJraWQiOiIwZDk5OTI4My1kZTM0LTQwMjYtODk5Mi1jYTRlM2EzMzUyODMiLCJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiUlMyNTYifQ.eyJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvd2FsbGV0L2RpcmVjdF9wb3N0Iiwic2NvcGUiOiJvcGVuaWQiLCJjbGllbnRfaWRfc2NoZW1lIjoicHJlLXJlZ2lzdGVyZWQiLCJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJpZF90b2tlbl90eXBlIjoic3ViamVjdF9zaWduZWRfaWRfdG9rZW4iLCJzdGF0ZSI6IktGbUpoVVRqWTJIQ2dYUFQ5MVVsWXNxUkVIcExJc1FITXlrSGluUUlMd2VpQUZ1Wm1Wb2Etb3M0eVNhQUpjZVltZVFUMkxvYWJlcE9GTGJsRkdycWV3IiwiaWF0IjoxNjg5NzcyMzI2LCJub25jZSI6Im5vbmNlIiwiY2xpZW50X2lkIjoiVmVyaWZpZXIiLCJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6IjBkOTk5MjgzLWRlMzQtNDAyNi04OTkyLWNhNGUzYTMzNTI4MyIsImlhdCI6MTY4OTc3MjIzMywibiI6ImtwT3RkemFhdGp2ODZqWE5ETm5OYVVub3Y5ZnpnTzhWUmNkWEQ2U01VWk56U0xwRWo0U2JfQ0pRS0o0X0JaOS05eFRUOWtCbV8xanVKQ3lGem0yZ2llZDlQU3J4VHFCTEpTcGZ2ZHFwOXo4bTJJenlid1ZxRnRBQXhwNHBvUkVPQ2dXYlloXzR3YVIyWmFEZkdMYWNLdlJfNTM3alJLTm0wT2J6NG5iOFFPalUzU0VLR2JXRFpPelVCaFB4MndObTlkNVU3YXFOZGZkM3VfaEg3ZmJFNjZhMHYyV3R2bmR3a05WZE9CaXhZMUY3QzVFQUc4bDF1dU1SVmZuWnZQS3d6dUVoR25MZTNCMkh4UzVXdk1rLTNBbHlaT2RDcDZiUmxiNEoyRGF1Zlp3cGNPek9Gc05VUFRKbHVKd1p5SzdndjNRSk9zVHNmSTNFYVRqdmRuY1VEdyJ9XX0sImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9hbGciOiJSUzI1NiIsImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMTI4Q0JDLUhTMjU2Iiwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbInVybjppZXRmOnBhcmFtczpvYXV0aDpqd2stdGh1bWJwcmludCIsImRpZDpleGFtcGxlIiwiZGlkOmtleSJdLCJpZF90b2tlbl9zaWduZWRfcmVzcG9uc2VfYWxnIjoiUlMyNTYifSwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0In0.CRPSsPMevO5hy-Y5nwKTzgEoiYuvPviOmw4TVCYk402b_6O5szlkRI82e2z6bLdbgH2LB1Xk_OAe57czNXGBkTwiCUcrrPHaJBkTcsHBKDCrdJ8ADc7BhI3aufA2BCrPa_hWNpnJfJQfQ8IszvKgksnjc_8xfUXLJM6dXRsyHlWxS42gTx67FOsUWEAnk2LI5M77pCvnwJUOXnGMAFg4YuWMEwgyuJQw_QrHR5TANcVu3cH8b_PtZfLodd8bpudFHJ_gh8bHY7KgcCGI5fvHun7yrpsYFhd2639N8AlZl_LvUcGnQ2WQB_IE9wZ60Q4LedxMhdvJbLWCZW9SkygkJw
Response_code: 200
Content-type: application/oauth-authz-req+jwt
```

and with JWT decoding:

```json
{
  "kid": "0d999283-de34-4026-8992-ca4e3a335283",
  "typ": "oauth-authz-req+jwt",
  "alg": "RS256"
}
```
```json
{
  "response_uri": "http://localhost:8080/wallet/direct_post",
  "scope": "openid",
  "client_id_scheme": "pre-registered",
  "response_type": "id_token",
  "id_token_type": "subject_signed_id_token",
  "state": "KFmJhUTjY2HCgXPT91UlYsqREHpLIsQHMykHinQILweiAFuZmVoa-os4ySaAJceYmeQT2LoabepOFLblFGrqew",
  "iat": 1689772326,
  "nonce": "nonce",
  "client_id": "Verifier",
  "client_metadata": {
    "jwks": {
      "keys": [
        {
          "kty": "RSA",
          "e": "AQAB",
          "use": "sig",
          "kid": "0d999283-de34-4026-8992-ca4e3a335283",
          "iat": 1689772233,
          "n": "kpOtdzaatjv86jXNDNnNaUnov9fzgO8VRcdXD6SMUZNzSLpEj4Sb_CJQKJ4_BZ9-9xTT9kBm_1juJCyFzm2gied9PSrxTqBLJSpfvdqp9z8m2IzybwVqFtAAxp4poREOCgWbYh_4waR2ZaDfGLacKvR_537jRKNm0Obz4nb8QOjU3SEKGbWDZOzUBhPx2wNm9d5U7aqNdfd3u_hH7fbE66a0v2WtvndwkNVdOBixY1F7C5EAG8l1uuMRVfnZvPKwzuEhGnLe3B2HxS5WvMk-3AlyZOdCp6bRlb4J2DaufZwpcOzOFsNUPTJluJwZyK7gv3QJOsTsfI3EaTjvdncUDw"
        }
      ]
    },
    "id_token_encrypted_response_alg": "RS256",
    "id_token_encrypted_response_enc": "A128CBC-HS256",
    "subject_syntax_types_supported": [
      "urn:ietf:params:oauth:jwk-thumbprint",
      "did:example",
      "did:key"
    ],
    "id_token_signed_response_alg": "RS256"
  },
  "response_mode": "direct_post"
}
```

## Submit Wallet Response - Direct Post

Sequence diagram interaction:
- ISO(12) HTTPs POST to response_uri [section B.3.2.2]
- ISO(14) OK: HTTP 200 with redirect_uri
- OIDVP(5) Authorisation Response (VP Token, state)
- OIDVP(6) Response (redirect_uri with response_code)

```bash
STATE=KFmJhUTjY2HCgXPT91UlYsqREHpLIsQHMykHinQILweiAFuZmVoa-os4ySaAJceYmeQT2LoabepOFLblFGrqew
cat >claims.json <<EOF
{
  "state": "${STATE}",
  "id_token": "1234"
}
EOF
JWT_SECRET="silly" mk-jwt-token.sh claims.json > token.jwt
cat token.jwt

curl -v -X POST 'http://localhost:8080/wallet/direct_post' \
  -H "Content-type: application/x-www-form-urlencoded" \
  -H "Accept: application/json" \
  --data-urlencode response@- < token.jwt
```

```HTTP
HTTP/1.1 200 OK
```

## Get Wallet Response - Direct Post

Sequence diagram interaction:
- ISO(18) get the data from Authorisation Response session
- ISO(20) return status and conditionally return data
- OIDVP(8) fetch response data (transaction-id, response_code)
- OIDVP(9) response data (VP Token, Presentation Submission)

```bash
curl -v --http1.1 \
  -X GET \
  -H "Accept: application/json" \
  'http://localhost:8080/ui/presentations/baDc1Sfebu01dbXoGDQjUbMsclddgVed97gdPXqOzY-gRUP-rRfK8wlHXtims2pSZSXHeaH5RMOVyAF1OhdOxQ?nonce=nonce' \
  | jq .
```

Response:

```json
{"id_token":"1234"}
```
