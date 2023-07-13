# EUDI Verifier Endpoint - Howto id_token request using direct_post

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Example of this scenario:
- Request for id_token
- Submit Wallet Response - Direct Post

## Table of contents

* [verifier to verifier backend, to post request for id_token](#requesting-a-idtoken)
* [wallet to verifier backend, to get request](#getting-the-request-object)
* [wallet to verifier backend, to post wallet response, an idToken](#submit-wallet-response---direct-post)
* [verifier to verifier backend, to get the wallet response](#get-wallet-response---direct-post)

## Requesting a id_token & vp_token

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
  "presentation_id":"x2OTSxlii7qp0hSMl7WHZlNWIjpE9Hq0CBPFP0scJsZBa5_gR1YbVKVZgCeGtBHusUuViNo1H4ZMIKqYGbQXIA",
  "client_id":"Verifier",
  "request_uri":"http://localhost:8080/wallet/request.jwt/nMjAkIxcioqzQ6c-GzvL4UKJ7UdZHNqeV4jNSqS-H-mLnMM83Cff7N5Hvf49ak5ibroaO-1skCsKTTcxeu0Owg"
}
```

## Getting the request object

Sequence diagram interaction:
- ISO(6) get request object
- ISO(7) JWS Authorisation request object [section B.3.2.1]

Accessing the request_uri:

```bash
curl "http://localhost:8080/wallet/request.jwt/nMjAkIxcioqzQ6c-GzvL4UKJ7UdZHNqeV4jNSqS-H-mLnMM83Cff7N5Hvf49ak5ibroaO-1skCsKTTcxeu0Owg"
```

returns:
```base64
eyJraWQiOiIxMDIzOWVmOS1iYzVhLTRiZjQtYmM2MC0yNTQ4ZWVjZjk1YmIiLCJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiUlMyNTYifQ.eyJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvd2FsbGV0L2RpcmVjdF9wb3N0Iiwic2NvcGUiOiJvcGVuaWQiLCJjbGllbnRfaWRfc2NoZW1lIjoicHJlLXJlZ2lzdGVyZWQiLCJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJpZF90b2tlbl90eXBlIjoic3ViamVjdF9zaWduZWRfaWRfdG9rZW4iLCJzdGF0ZSI6Im5NakFrSXhjaW9xelE2Yy1HenZMNFVLSjdVZFpITnFlVjRqTlNxUy1ILW1Mbk1NODNDZmY3TjVIdmY0OWFrNWlicm9hTy0xc2tDc0tUVGN4ZXUwT3dnIiwiaWF0IjoxNjg4NTYwODkyLCJub25jZSI6Im5vbmNlIiwiY2xpZW50X2lkIjoiVmVyaWZpZXIiLCJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6IjEwMjM5ZWY5LWJjNWEtNGJmNC1iYzYwLTI1NDhlZWNmOTViYiIsImlhdCI6MTY4ODU2MDgyMSwibiI6IndHOXRlcUx0NWg3eTdDLXlwcTJCS0doVzJtMGdFWnU2d3lWMkYzdEVfOFBOYVRwb002NHYwb2J5eWRsWkFQWENwcDNGNWxWajRrb2d5OVNGRXNydzZ3aV9YaWg2elpzNnlaVXBndFc2OGl5ZnoxTE1HNFg1WGFveXdEOGxLQTc0V1lXUEEzVVlROXEyaWFwUEhGaXdGNGZyd3I4NURJLVc2SEtKd29aYVBrZzNoSDlYRUpibXVxQldxWHVMaFRzbG0xRUEwVWNTMHNsTG1zWV9qUDZSVFFIeUswRkdQSkVPelY4Rlg4T0x1X1VIdjhqd09wWUlPQ2pkRFhhQjdYU2RZY2k4bEVFRzNDMXdDR01zRmhsTktTeXdHcVVJVU1xQW9UR3lrMlFJdkRPY01XVXF1eHVEQTR1c2p2a25CekhTdmE3bjNkNXpfcGxQOWZoMDk0cmtHUSJ9XX0sImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9hbGciOiJSUzI1NiIsImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMTI4Q0JDLUhTMjU2Iiwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbInVybjppZXRmOnBhcmFtczpvYXV0aDpqd2stdGh1bWJwcmludCIsImRpZDpleGFtcGxlIiwiZGlkOmtleSJdLCJpZF90b2tlbl9zaWduZWRfcmVzcG9uc2VfYWxnIjoiUlMyNTYifSwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0In0.dLKVWwPSjPGttOpJ-Ci0RCzrCNSB2QNyTnfVjmggT-rTQBXpUh4zb0H_2xex_UFd9gZFOcp0hEnFK9jVSxehMH2QokFlIU58HaUH6VAoyIWLGn_WlnAVpxGzgGhWuM5SfK9eIXIwCcew651YSNR2HgOGki4r6pk_DjzLAPMaGDo6e9OTjSfLAolvUyx8rNnrTsNJCyevksOkO3mbSzjhZdTj496hHKs_3iFTHvXMNWDymoKDstLgjUlPceJ_RzlpO7Nk0HcRIrhGhVrac0qukCRqssb32I84991BAOji3MJkdWY4kaBaEXUHjxqAj74m3OQpzLNkHfwWkeOaGTVXig
```

and with JWT decoding:

```json
{
  "kid": "10239ef9-bc5a-4bf4-bc60-2548eecf95bb",
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
  "state": "nMjAkIxcioqzQ6c-GzvL4UKJ7UdZHNqeV4jNSqS-H-mLnMM83Cff7N5Hvf49ak5ibroaO-1skCsKTTcxeu0Owg",
  "iat": 1688560892,
  "nonce": "nonce",
  "client_id": "Verifier",
  "client_metadata": {
    "jwks": {
      "keys": [
        {
          "kty": "RSA",
          "e": "AQAB",
          "use": "sig",
          "kid": "10239ef9-bc5a-4bf4-bc60-2548eecf95bb",
          "iat": 1688560821,
          "n": "wG9teqLt5h7y7C-ypq2BKGhW2m0gEZu6wyV2F3tE_8PNaTpoM64v0obyydlZAPXCpp3F5lVj4kogy9SFEsrw6wi_Xih6zZs6yZUpgtW68iyfz1LMG4X5XaoywD8lKA74WYWPA3UYQ9q2iapPHFiwF4frwr85DI-W6HKJwoZaPkg3hH9XEJbmuqBWqXuLhTslm1EA0UcS0slLmsY_jP6RTQHyK0FGPJEOzV8FX8OLu_UHv8jwOpYIOCjdDXaB7XSdYci8lEEG3C1wCGMsFhlNKSywGqUIUMqAoTGyk2QIvDOcMWUquxuDA4usjvknBzHSva7n3d5z_plP9fh094rkGQ"
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

## Submit Wallet Response - Direct Post JWT

Sequence diagram interaction:
- ISO(12) HTTPs POST to response_uri [section B.3.2.2]
- ISO(14) OK: HTTP 200 with redirect_uri
- OIDVP(5) Authorisation Response (VP Token, state)
- OIDVP(6) Response (redirect_uri with response_code)

```bash
STATE=nMjAkIxcioqzQ6c-GzvL4UKJ7UdZHNqeV4jNSqS-H-mLnMM83Cff7N5Hvf49ak5ibroaO-1skCsKTTcxeu0Owg
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
  'http://localhost:8080/ui/presentations/x2OTSxlii7qp0hSMl7WHZlNWIjpE9Hq0CBPFP0scJsZBa5_gR1YbVKVZgCeGtBHusUuViNo1H4ZMIKqYGbQXIA?nonce=nonce' \
  | jq .
```

Response:

```json
{"id_token":"1234"}
```
