[![Build status](https://img.shields.io/github/workflow/status/andrewrigas/oath/Continuous%20Integration.svg)](https://github.com/andrewrigas/oath/actions)
[![Coverage status](https://img.shields.io/codecov/c/github/andrewrigas/oath/master.svg)](https://codecov.io/github/andrewrigas/oath)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.andrewrigas/jwt-core_2.13.svg)](https://central.sonatype.dev/artifact/io.github.andrewrigas/jwt-core_2.13/0.0.6)

## OATH

__OATH__ provides a set of tools for WEB Applications 
1. CSRF token generation 
2. Authentication (Issuing JWT Tokens) 
3. Authorization (Verifying JWT Tokens)

### Modules

* [CSRF](./csrf/README.md) - Token generator library
* [JWT](./jwt/README.md) - A Scala API of [java-jwt](https://github.com/auth0/java-jwt) Issuer and Verifier
* [Juror](./juror/README.md) - Extension of JWT to manipulate multiple tokens

### SBT Dependencies

* [csrf-core](https://mvnrepository.com/artifact/io.github.andrewrigas/csrf-core)
* [jwt-core](https://mvnrepository.com/artifact/io.github.andrewrigas/jwt-core)
* [juror-core](https://mvnrepository.com/artifact/io.github.andrewrigas/juror-core)

```scala
libraryDependencies += "io.github.andrewrigas" %% "csrf-core" % "0.0.6"
libraryDependencies += "io.github.andrewrigas" %% "jwt-core" % "0.0.0"
libraryDependencies += "io.github.andrewrigas" %% "juror-core" % "0.0.6"
```

### Json Converters

* [jwt-circe](https://mvnrepository.com/artifact/io.github.andrewrigas/jwt-circe)
* [jwt-jsoniter-scala](https://mvnrepository.com/artifact/io.github.andrewrigas/jwt-jsoniter-scala)

```scala
libraryDependencies += "io.github.andrewrigas" %% "jwt-circe" % "0.0.0"
libraryDependencies += "io.github.andrewrigas" %% "jwt-jsoniter-scala" % "0.0.0"
```