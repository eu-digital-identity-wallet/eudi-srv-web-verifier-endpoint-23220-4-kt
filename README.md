# verifier
Web application (backend Restful service) that would allow somebody to trigger the presentation use case (cross device, remote presentation scenario).

## Build


Project depends on [Presentation Exchange](https://github.com/niscy-eudiw/presentation-exchange-kt)
Thus, you need to firstly clone this project, build it and publish the library to 
local maven repo. To do so, from within the cloned directory run

```bash
./grandlew clean build publishToMavenLocal
```

Then switch to this project folder and run

```bash
./grandlew build
```

Clean up

```bash
./grandlew clean
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