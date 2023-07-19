# EUDI Verifier Endpoint - Howto vp_token & id_token request using direct_post.jwt

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Example of this scenario:
- Request for id_token
- Submit Wallet Response - Direct Post JWT

## Table of contents

* [verifier to verifier backend, to post request for id_token](#requesting-a-vptoken)
* [wallet to verifier backend, to get request](#getting-the-request-object)
* [wallet to verifier backend, to post wallet response, an idToken](#submit-wallet-response---direct-post)
* [verifier to verifier backend, to get the wallet response](#get-wallet-response---direct-post)

## Requesting a vp_token

Sequence diagram interaction:
- ISO(1) prepare request_uri
- OIDVP(2) initiate transaction
- OIDVP(3) return transaction-id & request-id

```bash
curl -X POST -H "Content-type: application/json" -d '{
  "type": "vp_token id_token",
  "id_token_type": "subject_signed_id_token",
  "presentation_definition": {
    "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
    "input_descriptors": [
      {
        "id": "wa_driver_license",
        "name": "Washington State Business License",
        "purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
        "constraints": {
          "fields": [
            {
              "path": [
                "$.credentialSubject.dateOfBirth",
                "$.credentialSubject.dob",
                "$.vc.credentialSubject.dateOfBirth",
                "$.vc.credentialSubject.dob"
              ]
            }
          ]
        }
      }
    ]
  },
  "nonce": "nonce"
}' 'http://localhost:8080/ui/presentations'
```

Successful output looks like:

```json
{
  "presentation_id":"IA9lCRnlxIWU7xQeAviu1SumdTYZYWKIi4Sen40Q9_aK1HTuU63UqKMOEw3XOfnIn0lP844tMxU8hLltf_5cUw",
  "client_id":"Verifier",
  "request_uri":"http://localhost:8080/wallet/request.jwt/upUZ9PJ9mwgAQcmqkF-EDqE8-Ev5zsjQRrauPxZcHgp9fEfSe8lifk9KpybNqY2iXw58JKxkOgdxi2Fgbbz61w"
}
```

## Getting the request object

Sequence diagram interaction:
- ISO(6) get request object
- ISO(7) JWS Authorisation request object [section B.3.2.1]

Accessing the request_uri:

```bash
curl "http://localhost:8080/wallet/request.jwt/upUZ9PJ9mwgAQcmqkF-EDqE8-Ev5zsjQRrauPxZcHgp9fEfSe8lifk9KpybNqY2iXw58JKxkOgdxi2Fgbbz61w"
```

returns:
```base64
eyJraWQiOiI0OWMyMDQzZS1lZTQyLTRiMzItYjRlNC1hYzQzOWNlODNmZTgiLCJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiUlMyNTYifQ.eyJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvd2FsbGV0L2RpcmVjdF9wb3N0IiwiY2xpZW50X2lkX3NjaGVtZSI6InByZS1yZWdpc3RlcmVkIiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIGlkX3Rva2VuIiwiaWRfdG9rZW5fdHlwZSI6InN1YmplY3Rfc2lnbmVkX2lkX3Rva2VuIiwibm9uY2UiOiJub25jZSIsImNsaWVudF9pZCI6IlZlcmlmaWVyIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0IiwiYXVkIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92MiIsInNjb3BlIjoib3BlbmlkIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiIzMmY1NDE2My03MTY2LTQ4ZjEtOTNkOC1mZjIxN2JkYjA2NTMiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJ3YV9kcml2ZXJfbGljZW5zZSIsIm5hbWUiOiJXYXNoaW5ndG9uIFN0YXRlIEJ1c2luZXNzIExpY2Vuc2UiLCJwdXJwb3NlIjoiV2UgY2FuIG9ubHkgYWxsb3cgbGljZW5zZWQgV2FzaGluZ3RvbiBTdGF0ZSBidXNpbmVzcyByZXByZXNlbnRhdGl2ZXMgaW50byB0aGUgV0EgQnVzaW5lc3MgQ29uZmVyZW5jZSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLmNyZWRlbnRpYWxTdWJqZWN0LmRhdGVPZkJpcnRoIiwiJC5jcmVkZW50aWFsU3ViamVjdC5kb2IiLCIkLnZjLmNyZWRlbnRpYWxTdWJqZWN0LmRhdGVPZkJpcnRoIiwiJC52Yy5jcmVkZW50aWFsU3ViamVjdC5kb2IiXX1dfX1dfSwic3RhdGUiOiJ1cFVaOVBKOW13Z0FRY21xa0YtRURxRTgtRXY1enNqUVJyYXVQeFpjSGdwOWZFZlNlOGxpZms5S3B5Yk5xWTJpWHc1OEpLeGtPZ2R4aTJGZ2JiejYxdyIsImlhdCI6MTY4ODU3ODg1NSwiY2xpZW50X21ldGFkYXRhIjp7Imp3a3MiOnsia2V5cyI6W3sia3R5IjoiUlNBIiwiZSI6IkFRQUIiLCJ1c2UiOiJzaWciLCJraWQiOiI0OWMyMDQzZS1lZTQyLTRiMzItYjRlNC1hYzQzOWNlODNmZTgiLCJpYXQiOjE2ODg1NzgzMzgsIm4iOiJ1bHdxaEdzSWJuWTl4SkhUZUtMNmRYYk9FbVlVYk15cEExcDFMcUVsTk1DY3hDX3VZbG01enJUb0pUZzA1MnIyRkRsaXp2aDdyeWdNUnBqVFY0RUVQYi1iUWk3YWVWWW9YWVpKcFZZODlHUlFhdnB3RjZNdFhuX1BxWU5HclJ1N2pqVF9Jem00T200V2IzdFVqeE0tQTFFWk80MzZYNkRpTHhFdkJzdnlNd3NkNFQ5Ykpra0xRWWYzdURUYXRGY2FNRXV2LUI0Z2R6OWw3bDNhdlhzcnhyT3RfcXpOd3VzbU4yUTY5a25pRm1HUHQzV2pFdjlJb2xCam96UDlhb1pvSS1GNkM4dERkN1BzZDJ0MkFLNmFJbjFtdVJmYUNlcjlfTlJ3UDF2RFRlMU1tN0RxRDB5LXpmeUM3MkQ1QUlEdXJIRnJSYnhXWDIwRlROdFRNTGlBWVEifV19LCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiUlMyNTYiLCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTEyOENCQy1IUzI1NiIsInN1YmplY3Rfc3ludGF4X3R5cGVzX3N1cHBvcnRlZCI6WyJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQiLCJkaWQ6ZXhhbXBsZSIsImRpZDprZXkiXSwiaWRfdG9rZW5fc2lnbmVkX3Jlc3BvbnNlX2FsZyI6IlJTMjU2In19.epWN2P7tpz0i8Dwq5B4t2ecg1vnCYUcMZ9qQ6Xi6uwJGvA41RxUJxlmdEC0pD46YgbFTHpdwa9-zLHe1rm1YsFtgRc8LHr5_aK_ZNsU-oMN5qeLFLS0t6mOadIUmXBZ5bmXqfJOm4F9n-JrDWHjOVL3JmtPwckIV7J5IW4m6s4SM7kB2uWFJZZWIQJkn4ceykhbeW7kxiXbXxs-lOcrcCAoovfmyZh10EgHboZ-hXVcswZA5AvLGAoN0qeP4oUfwglyNj1Q9GLVLn0gCRIY5H4iJmS7XcKithh5pmezXvLnVK17PKj1FKwZXHvPCWXjDXO9AqOs7M5jQkip4EcQx8Q
```

and with JWT decoding:

```json
{
  "response_uri": "http://localhost:8080/wallet/direct_post",
  "client_id_scheme": "pre-registered",
  "response_type": "vp_token id_token",
  "id_token_type": "subject_signed_id_token",
  "nonce": "nonce",
  "client_id": "Verifier",
  "response_mode": "direct_post",
  "aud": "https://self-issued.me/v2",
  "scope": "openid",
  "presentation_definition": {
    "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
    "input_descriptors": [
      {
        "id": "wa_driver_license",
        "name": "Washington State Business License",
        "purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
        "constraints": {
          "fields": [
            {
              "path": [
                "$.credentialSubject.dateOfBirth",
                "$.credentialSubject.dob",
                "$.vc.credentialSubject.dateOfBirth",
                "$.vc.credentialSubject.dob"
              ]
            }
          ]
        }
      }
    ]
  },
  "state": "upUZ9PJ9mwgAQcmqkF-EDqE8-Ev5zsjQRrauPxZcHgp9fEfSe8lifk9KpybNqY2iXw58JKxkOgdxi2Fgbbz61w",
  "iat": 1688578855,
  "client_metadata": {
    "jwks": {
      "keys": [
        {
          "kty": "RSA",
          "e": "AQAB",
          "use": "sig",
          "kid": "49c2043e-ee42-4b32-b4e4-ac439ce83fe8",
          "iat": 1688578338,
          "n": "ulwqhGsIbnY9xJHTeKL6dXbOEmYUbMypA1p1LqElNMCcxC_uYlm5zrToJTg052r2FDlizvh7rygMRpjTV4EEPb-bQi7aeVYoXYZJpVY89GRQavpwF6MtXn_PqYNGrRu7jjT_Izm4Om4Wb3tUjxM-A1EZO436X6DiLxEvBsvyMwsd4T9bJkkLQYf3uDTatFcaMEuv-B4gdz9l7l3avXsrxrOt_qzNwusmN2Q69kniFmGPt3WjEv9IolBjozP9aoZoI-F6C8tDd7Psd2t2AK6aIn1muRfaCer9_NRwP1vDTe1Mm7DqD0y-zfyC72D5AIDurHFrRbxWX20FTNtTMLiAYQ"
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
  }
}
```

## Submit Wallet Response - Direct Post

Sequence diagram interaction:
- ISO(12) HTTPs POST to response_uri [section B.3.2.2]
- ISO(14) OK: HTTP 200 with redirect_uri
- OIDVP(5) Authorisation Response (VP Token, state)
- OIDVP(6) Response (redirect_uri with response_code)

```bash
STATE="upUZ9PJ9mwgAQcmqkF-EDqE8-Ev5zsjQRrauPxZcHgp9fEfSe8lifk9KpybNqY2iXw58JKxkOgdxi2Fgbbz61w"
cat >claims.json <<EOF
{
  "state": "${STATE}",
  "id_token": "1234",
  "vp_token": "123456",
  "presentation_submission": "{\"id\": \"a30e3b91-fb77-4d22-95fa-871689c322e2\",\"definition_id\": \"32f54163-7166-48f1-93d8-ff217bdb0653\",\"descriptor_map\": [{\"id\": \"employment_input\",\"format\": \"jwt_vc\",\"path\": \"$\"}]}"
}
EOF
JWT_SECRET="silly" mk-jwt-token.sh claims.json > token.jwt
cat token.jwt
jwtd $(cat token.jwt)

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
  'http://localhost:8080/ui/presentations/IA9lCRnlxIWU7xQeAviu1SumdTYZYWKIi4Sen40Q9_aK1HTuU63UqKMOEw3XOfnIn0lP844tMxU8hLltf_5cUw?nonce=nonce' \
  | jq .
```

Response:

```json
{
  "id_token": "1234",
  "vp_token": "123456",
  "presentation_submission": {
    "id": "a30e3b91-fb77-4d22-95fa-871689c322e2",
    "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
    "descriptor_map": [
      {
        "id": "employment_input",
        "format": "jwt_vc",
        "path": "$"
      }
    ]
  }
}
```
