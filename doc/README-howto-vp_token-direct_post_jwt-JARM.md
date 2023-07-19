# EUDI Verifier Endpoint - Howto vp_token & id_token request using direct_post.jwt

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Scenario used in this howto:
- Request for vp_token and id_token
- Request Object
- Submit Wallet Response - Direct Post JWT - JARM

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
  "presentation_id":"mbx9yKJMkfuN4viXKi62K9i4VJVHf4alGMnJ0KzR6x0i1qN-RibKi8kuMMj38W1Ym8DNGeNXxTNpG7vnYl7Hrg",
  "client_id":"Verifier",
  "request_uri":"http://localhost:8080/wallet/request.jwt/j_zF5XxCd2Ii8e7Z80XhZur1ij3oqpTiP7Okv5zvzPxFzInEpYU9kiJKY8mILi_PPhr2IONtUU7rBBDelpIL4g"
}
```

## Getting the request object

Sequence diagram interaction:
- ISO(6) get request object
- RFC9101(5.2.3) Authorization Server Fetches Request Object
- ISO(7) JWS Authorisation request object [section B.3.2.1]
- JARM()

Accessing the request_uri:

```bash
curl "http://localhost:8080/wallet/request.jwt/j_zF5XxCd2Ii8e7Z80XhZur1ij3oqpTiP7Okv5zvzPxFzInEpYU9kiJKY8mILi_PPhr2IONtUU7rBBDelpIL4g"
```

returns:
```base64
eyJraWQiOiJlNDc1YjlhNy04NjQyLTQ4NzMtYWUyYS02MTJjMzRiM2RmZjgiLCJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiUlMyNTYifQ.eyJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvd2FsbGV0L2RpcmVjdF9wb3N0Iiwic2NvcGUiOiJvcGVuaWQiLCJjbGllbnRfaWRfc2NoZW1lIjoicHJlLXJlZ2lzdGVyZWQiLCJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJpZF90b2tlbl90eXBlIjoic3ViamVjdF9zaWduZWRfaWRfdG9rZW4iLCJzdGF0ZSI6ImpfekY1WHhDZDJJaThlN1o4MFhoWnVyMWlqM29xcFRpUDdPa3Y1enZ6UHhGekluRXBZVTlraUpLWThtSUxpX1BQaHIySU9OdFVVN3JCQkRlbHBJTDRnIiwiaWF0IjoxNjg3NTI3NTQyLCJub25jZSI6Im5vbmNlIiwiY2xpZW50X2lkIjoiVmVyaWZpZXIiLCJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6ImU0NzViOWE3LTg2NDItNDg3My1hZTJhLTYxMmMzNGIzZGZmOCIsImlhdCI6MTY4NzUyNzQ5MCwibiI6Inkzb2E3SDR3WFFrWWJEc1RvOUhnVTRtT3FueUJMNWxsbDQyX0l6SjM0aHRsQ0pTWGhDeHFpelcxaVpRMWpLX1dkNUVfN1ZLcDVCUHg5ekRDaUcxRkZpUDd6ZmxrcEFtbmJ0dHF2bDI1SDNGQml2ZGhtMktxYVY3VVZQOUN4S3ZZUzhpWnduOS1lczYzNXhrcnVEQmZMVWszTzVlR3ZLZFlfdkNKNGhUSWJaTnplU2h4Wkt4VkRTUkZTeDhldk9BdXBWM1ZSSFhqY1ozcmFPUF9iQV8tNHZWZC12eEtsXy1vNmZKd0pLdFVSXzhoSURELWJUaUJnb1pvQWpoQlNxbnJsUGpEMDdrcVFURHFRQm9hdXFQQUFRRE10M1hNZnJodGpFdkhyZTZLbDJjYmVxZmRadVBXYXQ2Z0RqTEpvQ1Etc094YlZmcElCTHF1cWtPTjRSa0pmdyJ9XX0sImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9hbGciOiJSUzI1NiIsImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMTI4Q0JDLUhTMjU2Iiwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbInVybjppZXRmOnBhcmFtczpvYXV0aDpqd2stdGh1bWJwcmludCIsImRpZDpleGFtcGxlIiwiZGlkOmtleSJdLCJpZF90b2tlbl9zaWduZWRfcmVzcG9uc2VfYWxnIjoiUlMyNTYifSwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0In0.bllXnKy6k7n1JRqZh9n5oOPEQbl1PYhMndnQ7vNFR8GFxwUKajXQ16H1vA2du0y8ON5LsPWV9L0iPHfp0XjO5O5JYw9rx6x-TB2rpwAv4qqO-EDX0fFvHNQox2DD1JufUmIfDQrlNzfL121M7e0pxXil6oJptImuy60EM-KAU9ZbsxOboMVH_0aO-g72wsDROQolL_I9U1G__oTDkOfMhYiAU4mT8i5-RYbiGGtT86R2uCivIoQLQlxkzUnf1qEjTgl01YJ0a0JXk4gyFvDXvVEdVt2pcxU5my_VEfXgQ-Y8EbwMiCvPEmH4tptTjesj_TIr_S7Oal7UEk7Qsuz8Gw
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
  "response_mode": "direct_post.jwt",
  "aud": "https://self-issued.me/v2",
  "scope": "openid",
  "presentation_definition": {
    "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
    "input_descriptor": "mso_mdoc",
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
  "state": "IsoY9VwZXJ8GS7zg4CEHsCNu-5LpAiPGjbwYssZ2nh3tnkhytNw2mNZLSFsKOwdG2Ww33hX6PUp6P9xImdS-qA",
  "iat": 1684765226,
  "client_metadata": {
    "authorization_signed_response_alg": "RS256",
    "authorization_encrypted_response_alg": "RS256",
    "authorization_encrypted_response_enc": "A128CBC-HS256",
    "jwks": {
      "keys": [
        {
          "kty": "RSA",
          "e": "AQAB",
          "use": "sig",
          "kid": "8768a5e8-3776-4344-9c95-9143de645e59",
          "iat": 1684765163,
          "n": "2e2OR6Cw3pyMqIOXqMLDOFKwlPmkfSvJRpaqIubiJ36fpwTTa4Jg4MwQCQfWMTDGYrkJgMZ3IGjUGRJ0Wlbl8QdNPTwgI99S89Ca1j8iNAqX6Z0RSB8Nx3SNzb2iv4SUd2S3WeX_47OCuRvHg0kXD9u9P60bXsyIM699DH5NT7PyI65IbzrMqMXewTwC7bZz29KdnhBa02wOo2DOpNaFeZCvcr-H6K1aYB_-ii4lmikmOvqJLi6bqb5ZQMdeQzpJbiqnnW8BulmUM0yXqM3HtGRkf0GkfFb-Y_v8BMubRthHTwMeaXMpTdRnED6FTOHkVMsS6z3i2ey8M-xf9zUJEw"
        },
        {
          "kty":"EC",
          "use":"enc",
          "crv":"P-256",
          "kid":"123",
          "x":"W_2nTuD2pIsdub98z_fE_tjvpNFdSXYQJyhRAOgHGM8",
          "y":"Q2PhwUPaIfNjxHwn12weNyrSL7-vRiSDS3RMn7m5OJw",
          "alg":"ECDH-ES"
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
  "supported_algorithm" : "TODO"
}
```
