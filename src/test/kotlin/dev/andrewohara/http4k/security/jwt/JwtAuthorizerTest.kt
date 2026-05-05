package dev.andrewohara.http4k.security.jwt

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSetRetrievalException
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jwt.JWTClaimsSet
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import org.http4k.core.Response
import org.http4k.core.Status.Companion.NOT_FOUND
import org.http4k.core.Uri
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset

class JwtAuthorizerTest {
    private val rsa = RsaProvider("testServer")

    @Test
    fun `process invalid jwt`() {
        val provider = JwtAuthorizer(
            keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
            lookup = { it.subject }
        )
        provider("lolcats").shouldBeNull()
    }

    @Test
    fun `process valid jwt for unauthorized user`() {
        val token = rsa.generate("subject")
        val provider = JwtAuthorizer(
            keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
            lookup = { null }
        )
        provider(token).shouldBeNull()
    }

    @Test
    fun `process local HS jwt`() {
        val hs = HmacProvider( "testServer")
        val token = hs.generate("sub1")
        hs.verify(token) shouldBe "sub1"
    }

    @Test
    fun `get verified subject`() {
        val token = rsa.generate("sub1")
        val provider = JwtAuthorizer(
            keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
            lookup = { it.subject }
        )

        provider(token) shouldBe "sub1"
    }

    @Test
    fun `process remote jwt`() {
        val token = rsa.generate("sub1")
        val provider = JwtAuthorizer(
            lookup =  { it.subject },
            keySelector = http4kJwsKeySelector(
                jwkUri = Uri.of("http://localhost/keys.jwks"),
                algorithm = JWSAlgorithm.RS256,
                http = jwkServer(
                    RSAKey.Builder(rsa.publicKey)
                        .keyUse(KeyUse.SIGNATURE)
                        .keyID("key1")
                        .build()
                        .toPublicJWK()
                )
            )
        )

        provider(token) shouldBe "sub1"
    }

    @Test
    fun `process remote jwt - 404`() {
        val provider = JwtAuthorizer(
            lookup = { it.subject },
            keySelector = http4kJwsKeySelector(
                jwkUri = Uri.of("http://localhost/keys.jwks"),
                algorithm = JWSAlgorithm.RS256,
                http = { Response(NOT_FOUND) }
            )
        )

        val jwt = rsa.generate("sub1")

        shouldThrow<JWKSetRetrievalException> {
            provider(jwt)
        }
    }

    @Test
    fun `verify issuer`() {
        val provider = JwtAuthorizer(
            lookup = { it.subject },
            keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
            exactMatchClaims = JWTClaimsSet.Builder()
                .issuer(rsa.issuer)
                .build()
        )

        val token = rsa.generate("sub1")
        provider(token) shouldBe "sub1"
    }

    @Test
    fun `verify audience`() {
        val provider = JwtAuthorizer(
            keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
            audience = setOf("foo", "bar"),
            lookup = { it.subject }
        )

        rsa.generate("sub1", audience = emptyList()).let(provider).shouldBeNull()
        rsa.generate("sub1", audience = listOf("foo")).let(provider).shouldNotBeNull()
        rsa.generate("sub1", audience = listOf("foo", "bar")).let(provider).shouldNotBeNull()
        rsa.generate("sub1", audience = listOf("foo", "bar", "baz")).let(provider).shouldNotBeNull()
        rsa.generate("sub1", audience = listOf("baz")).let(provider).shouldBeNull()
    }

    @Test
    fun `verify issuer - invalid`() {
        val provider = JwtAuthorizer(
            lookup = { it.subject },
            keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
            exactMatchClaims = JWTClaimsSet.Builder()
                .issuer("issuer2")
                .build()
        )

        val token = rsa.generate("sub1")
        provider(token).shouldBeNull()
    }

    @Test
    fun `verify extra claims`() {
        val provider = JwtAuthorizer(
            keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
            exactMatchClaims = JWTClaimsSet.Builder()
                .claim("foo", "1")
                .build(),
            requiredClaims = setOf("bar"),
            prohibitedClaims = setOf("baz"),
            lookup = { it.subject }
        )

        provider(rsa.generate("sub1")).shouldBeNull()
        provider(rsa.generate("sub1", "foo" to "1")).shouldBeNull()
        provider(rsa.generate("sub1", "foo" to "2", "bar" to "1")).shouldBeNull()
        provider(rsa.generate("sub1", "foo" to "1", "bar" to "1")).shouldNotBeNull()
        provider(rsa.generate("sub1", "foo" to "1", "bar" to "1", "baz" to "1")).shouldBeNull()
    }

    @Test
    fun `verify expiry`() {
        val clock = object: Clock() {
            override fun instant() = Instant.parse("2024-01-07T12:00:00Z")
            override fun withZone(zone: ZoneId?) = TODO()
            override fun getZone() = ZoneOffset.UTC
        }

        val provider = JwtAuthorizer(
            keySelector = SingleKeyJWSKeySelector(JWSAlgorithm.RS256, rsa.publicKey),
            lookup = { it.subject },
            clock = clock
        )

        rsa.generate("sub1", expires = clock.instant() - Duration.ofMinutes(1)).let(provider).shouldBeNull()
        rsa.generate("sub1", expires = clock.instant() + Duration.ofMinutes(1)).let(provider).shouldNotBeNull()
    }
}