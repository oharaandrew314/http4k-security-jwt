import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import dev.andrewohara.http4k.openapi.v3.JwtSecurity
import dev.andrewohara.http4k.security.jwt.JwtAuthorizer
import dev.andrewohara.http4k.security.jwt.RsaProvider
import org.http4k.contract.bindContract
import org.http4k.contract.contract
import org.http4k.core.Method.GET
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status.Companion.OK

/**
 * This example server uses http4k-security to add JWT authorization
 */
fun main() {
    // generate a new RSA key pair
    val rsa = RsaProvider("myapp.com")

    // authorize requests using the RSA public key
    val authorizer = JwtAuthorizer(
        keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
        lookup = { it.subject } // The principal is the JWT's subject
    )

    // Build a server protected by the JwtAuthorizer
    val http = contract {
        security = JwtSecurity(authorizer)
        routes += "/" bindContract GET to { _: Request -> Response(OK) }
    }

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