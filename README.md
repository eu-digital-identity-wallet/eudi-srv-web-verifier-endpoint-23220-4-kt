# verifier
Web application (backend Restful service) that would allow somebody to trigger the presentation use case (cross device, remote presentation scenario).

## Build


Project depends on [Presentation Exchange](https://github.com/niscy-eudiw/presentation-exchange-kt)
Thus, you need to firstly clone this project, build it and publish the library to 
local maven repo. To do so, from within the cloned directory run

```bash
./gradlew clean build publishToMavenLocal
```

Then switch to this project folder and run

```bash
./gradlew build
```

Clean up

```bash
./gradlew clean
```

## Build OCI Image

```bash
./gradlew bootBuildImage
```

## Example

Requesting a id_token & vp_token

```bash
curl -H "Content-type: application/json" -d '{
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
  }
}' 'http://localhost:8080/ui/presentations'
```

Successful output looks like:

```json
{
  "client_id":"Verifier",
  "request_uri":"http://localhost:8080/wallet/request.jwt/o8J8zSIppIFj6iBOHR-iE4HoTnxd3B3CVuh_E8kC_s0wFxwAUwJ6Xq0gFXL_bv9P7QvHSb3KBQ0V47_kYxOuTw"
}
```

Accessing the request_uri:

```bash
curl "http://localhost:8080/wallet/request.jwt/6si8XHRCzyxsN9swxkfgR7pw8JCggnCmnz0VN0H4gsoHxIaRiY4Z9Yg-VsUsXC5FpZPuqjpP3c3ZPbCeKzRUzg"
```

returns:
```base64
eyJraWQiOiIwNTg4ZjUxMS0wMGE2LTQ3ZDAtOTJmNC0wNTUyZDRlNzM3OGEiLCJhbGciOiJSUzI1NiJ9.eyJyZXNwb25zZV91cmkiOiJodHRwczovL2ZvbyIsImNsaWVudF9pZF9zY2hlbWUiOiJwcmUtcmVnaXN0ZXJlZCIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiBpZF90b2tlbiIsImlkX3Rva2VuX3R5cGUiOiJzdWJqZWN0X3NpZ25lZF9pZF90b2tlbiIsIm5vbmNlIjoiWFRXTnp3Y2tsLTgyemc0aURxV2dYb0l4dVhHSmV6eFZ1UG9RYWRneHJGay1RbVpCeDRFak41dE4xbURhRk5WNFMySGFfTTVsMVNjUFlDRE1rZzVzR0EiLCJjbGllbnRfaWQiOiJWZXJpZmllciIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJhdWQiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwic2NvcGUiOiJvcGVuaWQiLCJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6eyJpZCI6IjMyZjU0MTYzLTcxNjYtNDhmMS05M2Q4LWZmMjE3YmRiMDY1MyIsImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6IndhX2RyaXZlcl9saWNlbnNlIiwibmFtZSI6Ildhc2hpbmd0b24gU3RhdGUgQnVzaW5lc3MgTGljZW5zZSIsInB1cnBvc2UiOiJXZSBjYW4gb25seSBhbGxvdyBsaWNlbnNlZCBXYXNoaW5ndG9uIFN0YXRlIGJ1c2luZXNzIHJlcHJlc2VudGF0aXZlcyBpbnRvIHRoZSBXQSBCdXNpbmVzcyBDb25mZXJlbmNlIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQuY3JlZGVudGlhbFN1YmplY3QuZGF0ZU9mQmlydGgiLCIkLmNyZWRlbnRpYWxTdWJqZWN0LmRvYiIsIiQudmMuY3JlZGVudGlhbFN1YmplY3QuZGF0ZU9mQmlydGgiLCIkLnZjLmNyZWRlbnRpYWxTdWJqZWN0LmRvYiJdfV19fV19LCJzdGF0ZSI6IjZzaThYSFJDenl4c045c3d4a2ZnUjdwdzhKQ2dnbkNtbnowVk4wSDRnc29IeElhUmlZNFo5WWctVnNVc1hDNUZwWlB1cWpwUDNjM1pQYkNlS3pSVXpnIiwiaWF0IjoxNjgyMzMxMTIxfQ.bHwjJVoaljDT0hn5akeTQrsVnqZkGCSQdk9Z_scZQdA0qqj40YGUiD6ur2k4ngj59MKsWh9tXtwS_xfL9QQcXSeeE6_aOefGYnnn2Q4LHrFMikfWC2e8T4j3X8V_hL27MCGkJhl6g7FO8Z4KGDw9rzLmvRj9LURlIUtVID94izp_cQQ1qK0VKd8I-ooxwT75GwNGI4nH9FuW8wgKg15L_zjtZTR_ME41M_wOrM9nocEL2dO_OLd9j2KqazMrXQZxa2Qyh9y0NvhzqGzUcSCmKceGtl9tNSFSsOuCRxmoD-0HTvffYeC4BjJdadnEDm2J9c-gBZ94rHUZbjxE1z98mw
```

and with base64 decoding:

```json
{
  "response_uri": "https://foo",
  "client_id_scheme": "pre-registered",
  "response_type": "vp_token id_token",
  "id_token_type": "subject_signed_id_token",
  "nonce": "XTWNzwckl-82zg4iDqWgXoIxuXGJezxVuPoQadgxrFk-QmZBx4EjN5tN1mDaFNV4S2Ha_M5l1ScPYCDMkg5sGA",
  "client_id": "Verifier",
  "response_mode": "direct_post.jwt",
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
  "state": "6si8XHRCzyxsN9swxkfgR7pw8JCggnCmnz0VN0H4gsoHxIaRiY4Z9Yg-VsUsXC5FpZPuqjpP3c3ZPbCeKzRUzg",
  "iat": 1682331121
}
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct,
and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, 
see the [tags on this repository](https://github.com/eu-digital-identity-wallet/architecture-and-reference-framework/tags). 

## Authors

See the list of [contributors](https://github.com/eu-digital-identity-wallet/architecture-and-reference-framework/graphs/contributors) who participated in this project.

## License

This project is licensed under the [Attribution 4.0
International](http://creativecommons.org/licenses/by/4.0/) - see the
[LICENSE.txt](LICENSE) file for details.