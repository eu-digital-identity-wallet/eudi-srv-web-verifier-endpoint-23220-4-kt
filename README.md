# EUDI Verifier Endpoint

**Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## Table of contents

* [Overview](#overview)
* [Disclaimer](#disclaimer)
* [Presentation Flows](#presentation-flows)
* [How to build and run](#how-to-build-and-run)
* [Run all verifier components together](#run-all-verifier-components-together)
* [Endpoints](#endpoints)
* [Configuration](#configuration)
* [How to contribute](#how-to-contribute)
* [License](#license)

 
## Overview

This is a Web application (Backend Restful service) that acts as a Verifier/RP trusted end-point. 
This backend service is accompanied by a Web UI application implemented [here](https://github.com/eu-digital-identity-wallet/eudi-web-verifier). 

See section [Run all verifier components together](#run-all-verifier-components-together) on how to boot both applications together.

Application exposes two APIs
* [Verifier API](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/adapter/input/web/VerifierApi.kt)
* [Wallet API](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/adapter/input/web/WalletApi.kt)

The Verifier API, supports two operations:
* [Initialize Transaction](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/port/input/InitTransaction.kt), where Verifier may define whether it wants to request a SIOP or OpenID4VP or combined request
* [Get Wallet response](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/port/input/GetWalletResponse.kt), where Verifier receives depending on the request an `id_token`, `vp_token`, or an error  

An Open API v3 specification of these operations is available [here](src/main/resources/public/openapi.json).

The Wallet API, provides the following main operations
* [Get Request Object](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/port/input/GetRequestObject.kt) according JWT Secured Authorization Request
* [Get Presentation Definition](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/port/input/GetPresentationDefinition.kt) according to OpenId4VP in case of using `presentation_definition_uri`
* [Direct Post](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/port/input/PostWalletResponse.kt) according to OpenID4VP `direct_post`

Please note that 
* Both APIs need to be exposed over HTTPS.  
* Verifier API needs to be protected to allow only authorized access. 

Both of those concerns have not been tackled by the current version of the application, 
since in its current version is merely a development tool, rather a production application.

## Disclaimer

The released software is a initial development release version: 
-  The initial development release is an early endeavor reflecting the efforts of a short timeboxed period, and by no means can be considered as the final product.  
-  The initial development release may be changed substantially over time, might introduce new features but also may change or remove existing ones, potentially breaking compatibility with your existing code.
-  The initial development release is limited in functional scope.
-  The initial development release may contain errors or design flaws and other problems that could cause system or other failures and data loss.
-  The initial development release has reduced security, privacy, availability, and reliability standards relative to future releases. This could make the software slower, less reliable, or more vulnerable to attacks than mature software.
-  The initial development release is not yet comprehensively documented. 
-  Users of the software must perform sufficient engineering and additional testing in order to properly evaluate their application and determine whether any of the open-sourced components is suitable for use in that application.
-  We strongly recommend to not put this version of the software into production use.
-  Only the latest version of the software will be supported

## How to build and run

To start the service locally you can execute 
```bash
./gradlew bootRun
```
To build a local docker image of the service execute
```bash
./gradlew bootBuildImage
```

## Run all verifier components together

To start both verifier UI and verifier backend services together a docker compose file has been implemented that can be found [here](docker/docker-compose.yaml)
Running the command below will start the following service:
- verifier: The Verifier/RP trusted end-point 
- verifier-ui: The Verifier's UI application
- haproxy: A reverse proxy for SSL termination 
  - To change the ssl certificate update [haproxy.pem](docker/haproxy.pem)  
  - To reconfigure haproxy update file [haproxy.conf](docker/haproxy.conf)  

To start the docker compose environment
```bash
# From project root directory 
cd docker
docker-compose up -d
```
To stop the docker compose environment
```bash
# From project root directory 
cd docker
docker-compose down
```

The 'verifier' service can be configured by setting its configuration properties described [here](#configuration) by setting them as environment 
variables of the service in [docker-compose.yaml](docker/docker-compose.yaml)  

**Example:**
```yaml
  verifier:
    image: ghcr.io/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt:latest
    container_name: verifier-backend
    ports:
      - "8080:8080"
    environment:
      VERIFIER_PUBLICURL: "https://10.240.174.10"
      VERIFIER_RESPONSE_MODE: "DirectPost"
      VERIFIER_JAR_SIGNING_KEY_KEYSTORE: file:///keystore.jks
```

### Mount external keystore to be used with Authorization Request signing 
When property `VERIFIER_JAR_SIGNING_KEY` is set to `LoadFromKeystore` the service can be configured (as described [here](#when-verifier_jar_signing_key-is-set-to-loadfromkeystore-the-following-environment-variables-must-also-be-configured))
to read from a keystore the certificate used for signing authorization requests. 
To provide an external keystore mount it to the path designated by the value of property `VERIFIER_JAR_SIGNING_KEY_KEYSTORE`.   

**Example:**
```yaml
  verifier:
    image: ghcr.io/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt:latest
    container_name: verifier-backend
    ports:
      - "8080:8080"
    environment:
      VERIFIER_PUBLICURL: "https://10.240.174.10"
      VERIFIER_RESPONSE_MODE: "DirectPost"
      VERIFIER_JAR_SIGNING_KEY_KEYSTORE: file:///certs/keystore.jks
    volumes:
      - <PATH OF KEYSTORE IN HOST MACHINE>/keystore.jks:/certs/keystore.jks
      
```

## Presentation Flows

### Same device

```mermaid
sequenceDiagram    
    participant UA as User Agent
    participant W as Wallet
    participant V as Verifier
    participant VE as Verifier Endpoint
    UA->>V: Trigger presentation 
    
    V->>+VE: Initiate transaction
    VE-->>-V: Authorization request as request_url
    
    V->>UA: Render request as deep link
    UA->>W: Trigger wallet and pass request
    
    W->>+VE: Get authorization request via request_uri 
    VE-->>-W: authorization_request
    
    W->>W: Parse authorization request
    
    W->>+VE: Get presentation definition 
    VE-->>-W: presentation_definition
    
    W->>W: Prepare response     
    
    W->>+VE: Post vp_token response 
    VE->>VE: Validate response and prepare response_code
    VE-->>-W: Return redirect_uri with response_code
    
    W->>UA: Refresh user agent to follow redirect_uri
    UA->>V: Follow redirect_uri passing response_code
    
    V->>+VE: Get wallet response passing response_code 
    VE->>VE: Validate response_code matches wallet response
    VE-->>-V: Return wallet response
    
    V->>UA: Render wallet response 
```

### Cross device

```mermaid
sequenceDiagram    
    participant UA as User Agent
    participant W as Wallet
    participant V as Verifier
    participant VE as Verifier Endpoint
    UA->>V: Trigger presentation 
    
    V->>+VE:  Initiate transaction
    VE-->>-V: Authorization request as request_url
    
    V->>UA: Render request as QR Code

    loop
    V->>+VE: Get wallet response
    VE-->>-V: Return wallet response
    Note over V,VE: Verifier starts polling Verifier Endpoint for Wallet Response
    end

    UA->>W: Scan QR Code, trigger wallet, and pass request
    
    W->>+VE: Get authorization request via request_uri 
    VE-->>-W: authorization_request
    
    W->>W: Parse authorization request
    
    W->>+VE: Get presentation definition 
    VE-->>-W: presentation_definition
    
    W->>W: Prepare response     
    
    W->>+VE: Post vp_token response 
    VE->>VE: Validate response

    loop
    V->>+VE: Get wallet response
    VE-->>-V: Return wallet response
    end
    
    V->>UA: Render wallet response
```
## Endpoints

### Initialize transaction endpoint

- _Method_: POST
- _URL_: http://localhost:8080/ui/presentations
- _Actor_: [Verifier](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/adapter/input/web/VerifierApi.kt)

An endpoint to control the content of the authorization request that will be prepared from the verifier backend service. Payload of this request is a json object with the following acceptable attributes:
- `type`: The type of the response to the authorization request. Allowed values are one of: `id_token`, `vp_token` or `vp_token id_token`.
- `id_token_type`: In case type is `id_token` controls the type of id_token that will be requested from wallet. Allowed values are one of `subject_signed_id_token` or `attester_signed_id_token`. 
- `presentation_definition`: A json object that depicting the presentation definition to be included in the OpenId4VP authorization request in case `type` is 'vp_token'. 
- `nonce`: Nonce value to be included in the OpenId4VP authorization request.
- `response_mode`: Controls the `response_mode` attribute of the OpenId4VP authorization request. Allowed values are one of `direct_post` or `direct_post.jwt`.  
- `jar_mode`: Controls the way the generated authorization request will be passed. If 'by_value' the request will be passed inline to the wallet upon request, if `by_reference` a `request_uri` url will be returned.  
- `presentation_definition_mode`: Controls how the presentation definition will be embedded in the request. If 'by_value' it will be embedded inline, if `by_reference` a `presentation_definition_uri` url will be embedded in the request.
- `wallet_response_redirect_uri_template`: If provided will be used to construct the response to wallet, when it posts its response to the authorization request.   

**Usage:**
```bash
curl -X POST -H "Content-type: application/json" -d '{
  "type": "vp_token",  
  "presentation_definition": {
        "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "input_descriptors": [
            {
                "constraints": {
                    "fields": [
                        {
                            "intent_to_retain": false,
                            "path": [
                                "$['eu.europa.ec.eudiw.pid.1']['family_name']"
                            ]
                        }
                    ]
                },
                "id": "eu.europa.ec.eudiw.pid.1",
                "format": {
                  "mso_mdoc": {
                    "alg": [
                      "ES256",
                      "ES384",
                      "ES512",
                      "EdDSA"
                    ]
                  }
                }
                "name": "EUDI PID",
                "purpose": "We need to verify your identity"
            }
        ]
    },
  "nonce": "nonce"
}' 'http://localhost:8080/ui/presentations'
```

**Returns:**
```json
{
  "presentation_id": "STMMbidoCQTtyk9id5IcoL8CqdC8rxgks5FF8cqqUrHvw0IL3AaIHGnwxvrvcEyUJ6uUPNdoBQDa7yCqpjtKaw",
  "client_id": "dev.verifier-backend.eudiw.dev",
  "request_uri": "https://localhost:8080/wallet/request.jwt/5N6E7VZsmwXOGLz1Xlfi96MoyZVC3FZxwdAuJ26DnGcan-vYs-VAKErioQ58BWEsKlVw2_X49jpZHyp0Mk9nKw"
}
```

You can also try it out in [Swagger UI](http://localhost:8080/swagger-ui#/verifier%20api/initializeTransaction).

### Get authorization request

- _Method_: GET
- _URL_: http://localhost:8080/wallet/request.jwt/{transactionId}
- _Parameters_
  - `transactionId`: The initialized transaction's identifier
- _Actor_: [Wallet](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/adapter/input/web/WalletApi.kt)

An endpoint to be used by wallet when the OpenId4VP authorization request is passed to wallet by reference as a request_uri. 
The identifier returned from calling [Initialize transaction endpoint](#initialize-transaction-endpoint) end-point should be used to identify the request.  

**Usage:**
```bash
curl https://localhost:8080/wallet/request.jwt/5N6E7VZsmwXOGLz1Xlfi96MoyZVC3FZxwdAuJ26DnGcan-vYs-VAKErioQ58BWEsKlVw2_X49jpZHyp0Mk9nKw
```
**Returns:** The authorization request payload as a signed JWT. 

### Get presentation definition

- _Method_: GET
- _URL_: http://localhost:8080/wallet/pd/{transactionId}
- _Parameters_
    - `transactionId`: The initialized transaction's identifier
- _Actor_: [Wallet](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/adapter/input/web/WalletApi.kt)

An endpoint to be used by wallet when the presentation definition of the OpenId4VP authorization request is not embedded inline in the request but by reference as a `presentation_definition_uri`.

**Usage:**
```bash
curl https://localhost:8080/wallet/pd/5N6E7VZsmwXOGLz1Xlfi96MoyZVC3FZxwdAuJ26DnGcan-vYs-VAKErioQ58BWEsKlVw2_X49jpZHyp0Mk9nKw
```

**Returns:** The presentation definition of the authorization request as JSON.

### Send wallet response

- _Method_: POST
- _URL_: http://localhost:8080/wallet/direct_post
- _Actor_: [Wallet](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/adapter/input/web/WalletApi.kt)

An endpoint available to wallet to post its response. Based on the `response_mode` of the OpenId4VP authorization request this endpoint can 
accept 2 type of payloads:

_**response_mode = direct_post**_

A form post (application/x-www-form-urlencoded encoding) with the following form parameters:
- `state`: The state claim included in the authorization request JWT.
- `id_token`: The requested id_token if authorization request 'response_type' attribute contains `id_token`.
- `vp_token`: The requested vp_token if authorization request 'response_type' attribute contains `vp_token`.
- `presentation_submission`: The presentation submission accompanying the vp_token in case 'response_type' attribute of authorization request contains `vp_token`.

_**response_mode = direct_post.jwt**_

A form post (application/x-www-form-urlencoded encoding) with the following form parameters:
- `state`: The state claim included in the authorization request JWT.
- `response`: A string representing an encrypted JWT (JWE) that contains as claims the form parameters mentioned in the case above    

**Usage:**
```bash
STATE=IsoY9VwZXJ8GS7zg4CEHsCNu-5LpAiPGjbwYssZ2nh3tnkhytNw2mNZLSFsKOwdG2Ww33hX6PUp6P9xImdS-qA
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
**Returns:**

* Same device case
```HTTP
HTTP/1.1 200 OK
{
  "redirect_uri" : "https://dev.verifier.eudiw.dev/get-wallet-code?response_code=5272d373-ebab-40ec-b44d-0a9909d0da69"
}
```
* Cross device case
```HTTP
HTTP/1.1 200 OK
```

### Get wallet response

- Method: GET
- URL: http://localhost:8080/ui/presentations/{transactionId}?response_code={responseCode}
- Parameters
  - `transactionId`: The initialized transaction's identifier
  - `responseCode`: (OPTIONAL) Response code generated in case of 'same device' case 
- _Actor_: [Verifier](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/adapter/input/web/VerifierApi.kt)

```bash
curl http://localhost:8080/ui/presentations/5N6E7VZsmwXOGLz1Xlfi96MoyZVC3FZxwdAuJ26DnGcan-vYs-VAKErioQ58BWEsKlVw2_X49jpZHyp0Mk9nKw?response_code=5272d373-ebab-40ec-b44d-0a9909d0da69
```

**Returns:** The wallet submitted response as JSON.

You can also try it out in [Swagger UI](http://localhost:8080/swagger-ui#/verifier%20api/getWalletResponse).

### Get presentation event log

- Method: GET
- URL: http://localhost:8080/ui/presentations/{transactionId}/events
- Parameters
  - `transactionId`: The initialized transaction's identifier
- _Actor_: [Verifier](src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/adapter/input/web/VerifierApi.kt)

```bash
curl http://localhost:8080/ui/presentations/5N6E7VZsmwXOGLz1Xlfi96MoyZVC3FZxwdAuJ26DnGcan-vYs-VAKErioQ58BWEsKlVw2_X49jpZHyp0Mk9nKw?response_code=5272d373-ebab-40ec-b44d-0a9909d0da69/events
```

**Returns:** The log of notable events for the specific presentation.

You can also try it out in [Swagger UI](http://localhost:8080/swagger-ui#/verifier%20api/getPresentationEvents).

## Configuration

The Verifier Endpoint application can be configured using the following *environment* variables:

Variable: `SPRING_WEBFLUX_BASEPATH`  
Description: Context path for the Verifier Endpoint application.  
Default value: `/`

Variable: `SERVER_PORT`  
Description: Port for the HTTP listener of the Verifier Endpoint application  
Default value: `8080`

Variable: `VERIFIER_CLIENTID`  
Description: Client Id of the Verifier Endpoint application  
Default value: `Verifier`

Variable: `VERIFIER_CLIENTIDSCHEME`  
Description: Client Id Scheme used by the Verifier Endpoint application  
Possible values: `pre-registered`, `x509_san_dns`, `x509_san_uri`  
Default value: `pre-registered`

Variable: `VERIFIER_JAR_SIGNING_ALGORITHM`  
Description: Algorithm used to sign Authorization Request   
Possible values: Any `Algorithm Name` of an IANA registered asymmetric signature algorithm (i.e. Usage is `alg`):
https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms   
Note: The configured signing algorithm must be compatible with the configured signing key  
Default value: `RS256`

Variable: `VERIFIER_JAR_SIGNING_KEY`  
Description: Key to use for Authorization Request signing  
Possible values: `GenerateRandom`, `LoadFromKeystore`  
Setting this value to `GenerateRandom` will result in the generation of a random `RSA` key   
Note: The configured signing key must be compatible with the configured signing algorithm  
Default value: `GenerateRandom`

Variable: `VERIFIER_PUBLICURL`  
Description: Public URL of the Verifier Endpoint application  
Default value: `http://localhost:${SERVER_PORT}`

Variable: `VERIFIER_REQUESTJWT_EMBED`  
Description: How Authorization Requests will be provided    
Possible values: `ByValue`, `ByReference`  
Default value: `ByReference`

Variable: `VERIFIER_JWK_EMBED`  
Description: How the Ephemeral Keys used for Authorization Response Encryption will be provided in Authorization Requests    
Possible values: `ByValue`, `ByReference`  
Default value: `ByReference`

Variable: `VERIFIER_PRESENTATIONDEFINITION_EMBED`  
Description: How Presentation Definitions will be provided in Authorization Requests    
Possible values: `ByValue`, `ByReference`  
Default value: `ByValue`

Variable: `VERIFIER_RESPONSE_MODE`  
Description: How Authorization Responses are expected    
Possible values: `DirectPost`, `DirectPostJwt`  
Default value: `DirectPostJwt`

Variable: `VERIFIER_MAXAGE`  
Description: TTL of an Authorization Request  
Notes: Provide a value using Java Duration syntax  
Example: `PT6400M`  
Default value: `PT6400M`

Variable: `VERIFIER_PRESENTATIONS_CLEANUP_MAXAGE`  
Description: Age of Authorization Requests. Authorization Requests older than this, are deleted.     
Notes: Provide a value using Java Duration syntax  
Example: `P10D`  
Default value: `P10D`

Variable: `VERIFIER_CLIENTMETADATA_AUTHORIZATIONSIGNEDRESPONSEALG`  
Description: Accept only Authorization Responses that are _signed_ using this algorithm  
Possible values: Any `Algorithm Name` of an IANA registered asymmetric signature algorithm (i.e. Usage is `alg`):
https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms

Variable: `VERIFIER_CLIENTMETADATA_AUTHORIZATIONENCRYPTEDRESPONSEALG`  
Description: Accept only Authorization Responses that are _encrypted_ using this algorithm  
Possible values: Any `Algorithm Name` of an IANA registered asymmetric encryption algorithm (i.e. Usage is `alg`):
https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms  
Default value: `ECDH-ES`

Variable: `VERIFIER_CLIENTMETADATA_AUTHORIZATIONENCRYPTEDRESPONSEENC`  
Description: Accept only Authorization Responses that are _encrypted_ using this method  
Possible values: Any `Algorithm Name` of an IANA registered asymmetric encryption method (i.e. Usage is `enc`):
https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms    
Default value: `A128CBC-HS256`

Variable: `CORS_ORIGINS`  
Description: Comma separated list of allowed Origins for cross-origin requests  
Default value: `*`

Variable: `CORS_ORIGINPATTERNS`  
Description: Comma separated list of patterns used for more fine grained matching of allowed Origins for cross-origin requests  
Default value: `*`

Variable: `CORS_METHODS`  
Description: Comma separated list of HTTP methods allowed for cross-origin requests  
Default value: `*`

Variable: `CORS_HEADERS`  
Description: Comma separated list of allowed and exposed HTTP Headers for cross-origin requests  
Default value: `*`

Variable: `CORS_CREDENTIALS`  
Description: Whether credentials (i.e. Cookies or Authorization Header) are allowed for cross-origin requests
Default value: `false`

Variable: `CORS_MAXAGE`  
Description: Time in seconds of how long pre-flight request responses can be cached by clients  
Default value: `3600`

### When `VERIFIER_JAR_SIGNING_KEY` is set to `LoadFromKeystore` the following environment variables must also be configured.

Variable: `VERIFIER_JAR_SIGNING_KEY_KEYSTORE`  
Description: URL of the Keystore from which to load the Key to use for JAR signing  
Examples: `classpath:keystore.jks`, `file:///keystore.jks`

Variable: `VERIFIER_JAR_SIGNING_KEY_KEYSTORE_TYPE`  
Description: Type of the Keystore from which to load the Key to use for JAR signing  
Examples: `jks`, `pkcs12`

Variable: `VERIFIER_JAR_SIGNING_KEY_KEYSTORE_PASSWORD`  
Description: Password of the Keystore from which to load the Key to use for JAR signing

Variable: `VERIFIER_JAR_SIGNING_KEY_ALIAS`  
Description: Alias of the Key to use for JAR signing, in the configured Keystore

Variable: `VERIFIER_JAR_SIGNING_KEY_PASSWORD`  
Description: Password of the Key to use for JAR signing, in the configured Keystore


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
