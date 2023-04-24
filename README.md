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