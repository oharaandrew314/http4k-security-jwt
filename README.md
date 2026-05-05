[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# Http4k-security-jwt

A [nimbus-jose-jwt](https://connect2id.com/products/nimbus-jose-jwt) security plugin for [http4k/http4k](https://www.github.com/http4k/http4k)

### Installation

[![Maven Central Version](https://img.shields.io/maven-central/v/dev.andrewohara/http4k-security-jwt)](https://central.sonatype.com/artifact/dev.andrewohara/http4k-security-jwt)

### About

This module contains the http4k components necessary for a server to validate requests with a JWT bearer token.

It is NOT a token provider.

### Quickstart


```kotlin
fun main() {
    // generate a new RSA key pair
    val rsa = RsaProvider("exampleServer")

    // authorize requests using the RSA public key
    val authorizer = JwtAuthorizer(
        keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
        lookup = { it.subject } // The principal is the JWT's subject
    )

    // Build a server protected by the JwtAuthorizer
    val http = ServerFilters.JwtAuth(authorizer)
        .then { _: Request -> Response(OK) }

    // requests without a valid JWT will be rejected
    val unauthorizedRequest = Request(GET, "/")
        .header("Authorization", "Bearer letmein")

    println("Invalid JWT should be unauthorized:")
    println(http(unauthorizedRequest))

    // requests with a valid JWT will be allowed
    val authorizedRequest = Request(GET, "/")
        .header("Authorization", "Bearer ${rsa.generate("user1")}")

    println("Valid JWT should be successful:")
    println(http(authorizedRequest))
}
```

### Examples

[Examples Directory](https://github.com/oharaandrew314/http4k-security-jwt/tree/main/src/examples/kotlin)