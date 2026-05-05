package dev.andrewohara.http4k.openapi.v3

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import dev.andrewohara.http4k.security.jwt.JwtAuthorizer
import dev.andrewohara.http4k.security.jwt.RsaProvider
import org.http4k.contract.bindContract
import org.http4k.contract.contract
import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status
import org.http4k.kotest.shouldHaveBody
import org.http4k.kotest.shouldHaveStatus
import org.http4k.lens.RequestKey
import org.junit.jupiter.api.Test

class JwtSecurityTest {
    private val rsa = RsaProvider("testServer")

    private val authorizer = JwtAuthorizer(
        keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
        lookup = { it.subject.toIntOrNull() }
    )

    private val principal = RequestKey.required<Int>("principal")

    private val http = contract {
        security = JwtSecurity(authorizer, principal)
        routes += "/" bindContract Method.GET to { req: Request ->
            Response.Companion(Status.OK).body(principal(req).toString())
        }
    }

    @Test
    fun `valid jwt`() {
        val token = rsa.generate("1337")

        Request.Companion(Method.GET, "/")
            .header("Authorization", "Bearer $token")
            .let(http)
            .also { it shouldHaveStatus Status.OK }
            .shouldHaveBody("1337")
    }

    @Test
    fun `unauthorized jwt`() {
        val token = rsa.generate("foobarbaz")

        Request.Companion(Method.GET, "/")
            .header("Authorization", "Bearer $token")
            .let(http)
            .shouldHaveStatus(Status.UNAUTHORIZED)
    }
}