package dev.andrewohara.http4k.openapi.v3

import com.fasterxml.jackson.databind.JsonNode
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import dev.andrewohara.http4k.security.jwt.HmacProvider
import dev.andrewohara.http4k.security.jwt.JwtAuthorizer
import io.kotest.matchers.nulls.shouldNotBeNull
import org.http4k.core.ContentType
import org.http4k.format.Jackson
import org.http4k.testing.Approver
import org.http4k.testing.assertApproved
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.http4k.testing.JsonApprovalTest

@ExtendWith(JsonApprovalTest::class)
class JwtSecurityRendererTest {
    val security = JwtSecurity(
        JwtAuthorizer(
            keySelector = SingleKeyJWSKeySelector(
                JWSAlgorithm.HS256,
                HmacProvider("testServer").key
            ),
            lookup = { it.subject }
        )
    )
    val renderer = OpenApi3SecurityRendererWithJwt

    @Test
    fun ref(approver: Approver) {
        renderer.ref<JsonNode>(security).shouldNotBeNull().invoke(Jackson)
            .let(Jackson::asFormatString)
            .also { approver.assertApproved(it, ContentType.APPLICATION_JSON) }
    }

    @Test
    fun full(approver: Approver) {
        renderer.full<JsonNode>(security).shouldNotBeNull().invoke(Jackson)
            .let(Jackson::asFormatString)
            .also { approver.assertApproved(it, ContentType.APPLICATION_JSON) }
    }
}
