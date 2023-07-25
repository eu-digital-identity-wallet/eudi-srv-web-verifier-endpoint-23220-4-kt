# EUDI Verifier Endpoint - Howto vp_token request using direct_post

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Example of this scenario:
- Request for vp_token 
- Submit Wallet Response - Direct Post

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
  "presentation_id":"8cuLWnKzfaCXXy_tTeHVwdIfAf399saTLemVeis3GLnGxFVLP7EKNdfE2mZe7yB1N6EF4KRjNP3HF3VKrRRRBw",
  "client_id":"Verifier",
  "request_uri":"http://localhost:8080/wallet/request.jwt/YAPyrO1WPaOIqEpZSxe44XgSZNBEKPhAeVLKUlghLsK9ugK00UaNBsSYGL-K2bou3lckscarhvGmKjhyH1R5VQ"
}
```

## Getting the request object

Sequence diagram interaction:
- ISO(6) get request object
- ISO(7) JWS Authorisation request object [section B.3.2.1]

Accessing the request_uri:

```bash
curl "http://localhost:8080/wallet/request.jwt/YAPyrO1WPaOIqEpZSxe44XgSZNBEKPhAeVLKUlghLsK9ugK00UaNBsSYGL-K2bou3lckscarhvGmKjhyH1R5VQ"
```

returns:
```base64
eyJraWQiOiIxMDIzOWVmOS1iYzVhLTRiZjQtYmM2MC0yNTQ4ZWVjZjk1YmIiLCJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiUlMyNTYifQ.eyJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvd2FsbGV0L2RpcmVjdF9wb3N0IiwiY2xpZW50X2lkX3NjaGVtZSI6InByZS1yZWdpc3RlcmVkIiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIGlkX3Rva2VuIiwiaWRfdG9rZW5fdHlwZSI6InN1YmplY3Rfc2lnbmVkX2lkX3Rva2VuIiwibm9uY2UiOiJub25jZSIsImNsaWVudF9pZCI6IlZlcmlmaWVyIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0IiwiYXVkIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92MiIsInNjb3BlIjoib3BlbmlkIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiIzMmY1NDE2My03MTY2LTQ4ZjEtOTNkOC1mZjIxN2JkYjA2NTMiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJ3YV9kcml2ZXJfbGljZW5zZSIsIm5hbWUiOiJXYXNoaW5ndG9uIFN0YXRlIEJ1c2luZXNzIExpY2Vuc2UiLCJwdXJwb3NlIjoiV2UgY2FuIG9ubHkgYWxsb3cgbGljZW5zZWQgV2FzaGluZ3RvbiBTdGF0ZSBidXNpbmVzcyByZXByZXNlbnRhdGl2ZXMgaW50byB0aGUgV0EgQnVzaW5lc3MgQ29uZmVyZW5jZSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLmNyZWRlbnRpYWxTdWJqZWN0LmRhdGVPZkJpcnRoIiwiJC5jcmVkZW50aWFsU3ViamVjdC5kb2IiLCIkLnZjLmNyZWRlbnRpYWxTdWJqZWN0LmRhdGVPZkJpcnRoIiwiJC52Yy5jcmVkZW50aWFsU3ViamVjdC5kb2IiXX1dfX1dfSwic3RhdGUiOiJZQVB5ck8xV1BhT0lxRXBaU3hlNDRYZ1NaTkJFS1BoQWVWTEtVbGdoTHNLOXVnSzAwVWFOQnNTWUdMLUsyYm91M2xja3NjYXJodkdtS2poeUgxUjVWUSIsImlhdCI6MTY4ODU2NzE4MywiY2xpZW50X21ldGFkYXRhIjp7Imp3a3MiOnsia2V5cyI6W3sia3R5IjoiUlNBIiwiZSI6IkFRQUIiLCJ1c2UiOiJzaWciLCJraWQiOiIxMDIzOWVmOS1iYzVhLTRiZjQtYmM2MC0yNTQ4ZWVjZjk1YmIiLCJpYXQiOjE2ODg1NjA4MjEsIm4iOiJ3Rzl0ZXFMdDVoN3k3Qy15cHEyQktHaFcybTBnRVp1Nnd5VjJGM3RFXzhQTmFUcG9NNjR2MG9ieXlkbFpBUFhDcHAzRjVsVmo0a29neTlTRkVzcnc2d2lfWGloNnpaczZ5WlVwZ3RXNjhpeWZ6MUxNRzRYNVhhb3l3RDhsS0E3NFdZV1BBM1VZUTlxMmlhcFBIRml3RjRmcndyODVESS1XNkhLSndvWmFQa2czaEg5WEVKYm11cUJXcVh1TGhUc2xtMUVBMFVjUzBzbExtc1lfalA2UlRRSHlLMEZHUEpFT3pWOEZYOE9MdV9VSHY4andPcFlJT0NqZERYYUI3WFNkWWNpOGxFRUczQzF3Q0dNc0ZobE5LU3l3R3FVSVVNcUFvVEd5azJRSXZET2NNV1VxdXh1REE0dXNqdmtuQnpIU3ZhN24zZDV6X3BsUDlmaDA5NHJrR1EifV19LCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiUlMyNTYiLCJpZF90b2tlbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTEyOENCQy1IUzI1NiIsInN1YmplY3Rfc3ludGF4X3R5cGVzX3N1cHBvcnRlZCI6WyJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQiLCJkaWQ6ZXhhbXBsZSIsImRpZDprZXkiXSwiaWRfdG9rZW5fc2lnbmVkX3Jlc3BvbnNlX2FsZyI6IlJTMjU2In19.hJg7IZhsANfh3MyKbev7YiNn6SyJ7P4SCzHJeMcKwpIhB-doEZQd-szDc-ZgP6Id44eH51OlPV5Ih0wY2bYGPdUT--NGEyZqXzNevVFtYaeN-fcgrqgzMEjfHclbsNgFRgagirtZgMZltWoxDQQ2onL0mmrhV99FFouchwv6eZD93AGrILmpGg1nq_J5cVwV00dkjpSY-uz_OFz_5_u574OedkvoiI_sxXQ3uWz5vK8kOYFUQmGwsBGQODxoMMJd2sPbWDvlAAGYnlShjCzAh4POhgmkLHs9UNRZ3BTZGq-qe3N6rfhQdrPvlypxpFtUcU6bhSloVbAoeofHvVUgcA
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
  "state": "YAPyrO1WPaOIqEpZSxe44XgSZNBEKPhAeVLKUlghLsK9ugK00UaNBsSYGL-K2bou3lckscarhvGmKjhyH1R5VQ",
  "iat": 1688567183,
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
STATE=YAPyrO1WPaOIqEpZSxe44XgSZNBEKPhAeVLKUlghLsK9ugK00UaNBsSYGL-K2bou3lckscarhvGmKjhyH1R5VQ
curl -v -X POST 'http://localhost:8080/wallet/direct_post' \
  -H "Content-type: application/x-www-form-urlencoded" \
  -H "Accept: application/json" \
  --data-urlencode "state=$STATE" \
  --data-urlencode 'vp_token={"id": "123456"}' \
  --data-urlencode presentation_submission@- << EOF
{
  "id": "a30e3b91-fb77-4d22-95fa-871689c322e2",
  "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
  "descriptor_map": [
    {
      "id": "employment_input",
      "format": "jwt_vc",
      "path": "$.verifiableCredential[0]"
    }
  ]
}
EOF
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
  'http://localhost:8080/ui/presentations/8cuLWnKzfaCXXy_tTeHVwdIfAf399saTLemVeis3GLnGxFVLP7EKNdfE2mZe7yB1N6EF4KRjNP3HF3VKrRRRBw?nonce=nonce' \
  | jq .
```

Response:

```json
{

  "vp_token": {
    "id": "123456"
  },
  "presentation_submission": {
    "id": "a30e3b91-fb77-4d22-95fa-871689c322e2",
    "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
    "descriptor_map": [
      {
        "id": "employment_input",
        "format": "jwt_vc",
        "path": "$.verifiableCredential[0]"
      }
    ]
  }
}
```
