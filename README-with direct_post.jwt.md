# EUDI Verifier Endpoint

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## Table of contents

[Example id_token using direct_post.jwt](#example-idtoken-request-using-directpostjwt):

* [verifier to verifier backend, to post request for id_token](#requesting-a-idtoken)
* [wallet to verifier backend, to get request](#getting-the-request-object)
* [wallet to verifier backend, to post wallet response, an idToken](#submit-wallet-response---direct-post)
* [verifier to verifier backend, to get the wallet response](#get-wallet-response---direct-post)

## Example id_token request using direct_post.jwt

### Requesting a id_token

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
  "presentation_id":"mbx9yKJMkfuN4viXKi62K9i4VJVHf4alGMnJ0KzR6x0i1qN-RibKi8kuMMj38W1Ym8DNGeNXxTNpG7vnYl7Hrg",
  "client_id":"Verifier",
  "request_uri":"http://localhost:8080/wallet/request.jwt/j_zF5XxCd2Ii8e7Z80XhZur1ij3oqpTiP7Okv5zvzPxFzInEpYU9kiJKY8mILi_PPhr2IONtUU7rBBDelpIL4g"}
```

### Getting the request object

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
  "kid": "9870eab0-ece5-492c-9453-54ef5c04509e",
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
  "state": "j_zF5XxCd2Ii8e7Z80XhZur1ij3oqpTiP7Okv5zvzPxFzInEpYU9kiJKY8mILi_PPhr2IONtUU7rBBDelpIL4g",
  "iat": 1687527542,
  "nonce": "nonce",
  "client_id": "Verifier",
  "client_metadata": {
    "jwks": {
      "keys": [
        {
          "kty": "RSA",
          "e": "AQAB",
          "use": "sig",
          "kid": "e475b9a7-8642-4873-ae2a-612c34b3dff8",
          "iat": 1687527490,
          "n": "y3oa7H4wXQkYbDsTo9HgU4mOqnyBL5lll42_IzJ34htlCJSXhCxqizW1iZQ1jK_Wd5E_7VKp5BPx9zDCiG1FFiP7zflkpAmnbttqvl25H3FBivdhm2KqaV7UVP9CxKvYS8iZwn9-es635xkruDBfLUk3O5eGvKdY_vCJ4hTIbZNzeShxZKxVDSRFSx8evOAupV3VRHXjcZ3raOP_bA_-4vVd-vxKl_-o6fJwJKtUR_8hIDD-bTiBgoZoAjhBSqnrlPjD07kqQTDqQBoauqPAAQDMt3XMfrhtjEvHre6Kl2cbeqfdZuPWat6gDjLJoCQ-sOxbVfpIBLquqkON4RkJfw"
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

### Submit Wallet Response - Direct Post

- Method POST
- http://localhost:8080/wallet/direct_post

```bash
STATE=j_zF5XxCd2Ii8e7Z80XhZur1ij3oqpTiP7Okv5zvzPxFzInEpYU9kiJKY8mILi_PPhr2IONtUU7rBBDelpIL4g
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
### Get Wallet Response - Direct Post

```bash
curl -v --http1.1 \
  -X GET \
  -H "Accept: application/json" \
  'http://localhost:8080/ui/presentations/mbx9yKJMkfuN4viXKi62K9i4VJVHf4alGMnJ0KzR6x0i1qN-RibKi8kuMMj38W1Ym8DNGeNXxTNpG7vnYl7Hrg?nonce=nonce' 
  | jq .
```

Response:

```json
{"id_token":"1234"}
```

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
