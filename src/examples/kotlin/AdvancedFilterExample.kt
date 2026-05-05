import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import dev.andrewohara.http4k.filter.JwtAuth
import dev.andrewohara.http4k.security.jwt.JwtAuthorizer
import dev.andrewohara.http4k.security.jwt.RsaProvider
import org.http4k.core.Method.GET
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status.Companion.OK
import org.http4k.core.then
import org.http4k.filter.ServerFilters
import org.http4k.lens.RequestKey

/**
 * This slightly more advanced example will perform a user lookup after validating the JWT.
 */
fun main() {
    // generate a new RSA key pair
    val rsa = RsaProvider("exampleServer")

    val users = listOf(
        User("1", "user1@example.com"),
        User("2", "user2@example.com")
    )

    // authorize requests using the RSA public key
    val authorizer = JwtAuthorizer(
        keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
        // transform the subject into an Int and check if it's in the whitelist
        lookup = { claims -> users.find { it.id == claims.subject } }
    )

    // The authorizer will store the retrieved user in a request lens
    val userLens = RequestKey.required<User>("userId")

    /* Build a server protected by the JwtAuthorizer
     * The JWT filter will store the authorized principal in a lenn.
     * Then the server will return the user's email in the response body
     */
    val http = ServerFilters.JwtAuth(authorizer, userLens).then { request ->
        val user = userLens(request)
        Response(OK).body(user.emailAddress)
    }

    // Nonexistent users will be rejected, despite having a valid JWT
    val invalidSubjectRequest = Request(GET, "/")
        .header("Authorization", "Bearer ${rsa.generate("user1")}")

    println("Nonexisttend user should be unauthorized:")
    println(http(invalidSubjectRequest))

    // An existing user will be permitted
    val authorizedRequest = Request(GET, "/")
        .header("Authorization", "Bearer ${rsa.generate("2")}")

    println("User 2's email address:")
    println(http(authorizedRequest))
}

data class User(val id: String, val emailAddress: String)