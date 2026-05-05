package dev.andrewohara.http4k.filter

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import dev.andrewohara.http4k.security.jwt.JwtAuthorizer
import dev.andrewohara.http4k.security.jwt.RsaProvider
import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status.Companion.OK
import org.http4k.core.Status.Companion.UNAUTHORIZED
import org.http4k.core.then
import org.http4k.filter.ServerFilters
import org.http4k.kotest.shouldHaveBody
import org.http4k.kotest.shouldHaveStatus
import org.http4k.lens.RequestKey
import org.junit.jupiter.api.Test

class ServerFilterExtensionsTest {
    private val rsa = RsaProvider("testServer")
    private val authorizer = JwtAuthorizer(
        keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
        lookup = { if (it.subject == "user1") 1 else null }
    )

    private val principal = RequestKey.required<Int>("principal")

    private val http = ServerFilters.JwtAuth(authorizer, principal).then { req: Request ->
        Response(OK).body(principal(req).toString())
    }

    @Test
    fun `missing token`() {
        Request(Method.GET, "/")
            .let(http)
            .shouldHaveStatus(UNAUTHORIZED)
    }

    @Test
    fun `invalid token`() {
        Request(Method.GET, "/")
            .header("Authorization", "Bearer foo")
            .let(http)
            .shouldHaveStatus(UNAUTHORIZED)
    }

    @Test
    fun `valid token but unauthorized user`() {
        val token = rsa.generate("foo")

        Request(Method.GET, "/")
            .header("Authorization", "Bearer $token")
            .let(http)
            .shouldHaveStatus(UNAUTHORIZED)
    }

    @Test
    fun `valid token and authorized user`() {
        val token = rsa.generate("user1")

        Request(Method.GET, "/")
            .header("Authorization", "Bearer $token")
            .let(http)
            .also { it shouldHaveStatus OK }
            .shouldHaveBody("1")
    }
}