
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import dev.andrewohara.http4k.filter.JwtAuth
import dev.andrewohara.http4k.security.jwt.JwtAuthorizer
import dev.andrewohara.http4k.security.jwt.RsaProvider
import dev.andrewohara.http4k.security.jwt.http4kJwsKeySelector
import dev.andrewohara.http4k.security.jwt.jwkServer
import org.http4k.client.JavaHttpClient
import org.http4k.core.HttpHandler
import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status.Companion.OK
import org.http4k.core.Uri
import org.http4k.core.then
import org.http4k.filter.ServerFilters
import org.http4k.lens.uri
import org.http4k.routing.reverseProxy
import org.http4k.config.Environment
import org.http4k.config.EnvironmentKey
import org.http4k.kotest.shouldHaveStatus
import org.http4k.server.Jetty
import org.http4k.server.asServer
import org.junit.jupiter.api.Test

/**
 * This example shows how to instrument an application with a fake key source for testing
 */

private val issuerKey = EnvironmentKey.uri().required("ISSUER")

// The app factory that retrieves the public key from a remote JWK
fun createApp(
    env: Environment = Environment.ENV,
    internet: HttpHandler = JavaHttpClient()
): HttpHandler {
    // build an authorizer
    val authorizer = JwtAuthorizer(
        // get JWK from the ISSUER URI
        keySelector = http4kJwsKeySelector(
            jwkUri = env[issuerKey].path("jwk.json"),
            algorithm = JWSAlgorithm.RS256,
            http = internet
        ),

        // verify the JWT is from the ISSUER
        exactMatchClaims = JWTClaimsSet.Builder()
            .issuer(env[issuerKey].toString())
            .build(),

        // No database lookup; the JWT sub claim will be the user id
        lookup = { it.subject }
    )

    // protect the server with a filter
    return ServerFilters.JwtAuth(authorizer)
        .then { _: Request -> Response(OK) }
}

/*
 * When instrumenting for testing, we just need to build a fake JWK server and point our app to it
 */
class AppTest() {
    private val issuer = Uri.of("https://auth.fake")

    private val rsa = RsaProvider(issuer.toString())
    private val jwk = RSAKey.Builder(rsa.publicKey)
        .keyUse(KeyUse.SIGNATURE)
        .keyID("key1")
        .build()
        .toPublicJWK()

    // create a fake app
    private val app = createApp(
        // inject a fake issuer URI into the ENV
        env = Environment.defaults(issuerKey of issuer),

        // override the internet, returning a JWK from a fake issuer
        internet = reverseProxy("auth.fake" to jwkServer(jwk))
    )

    @Test
    fun `authorize request`() {
        val jwt = rsa.generate("user1")

        Request(Method.GET, "/")
            .header("Authorization", "Bearer $jwt")
            .let(app)
            .shouldHaveStatus(OK)
    }
}

/*
 * When creating a real app, we use the exact same factory method, but without any overrides.
 * The issuer URI is retrieved from the ENV, like normal
 */
fun main() {
    createApp()
        .asServer(Jetty(8000))
        .start()
}