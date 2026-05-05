package dev.andrewohara.http4k.openapi.v3

import org.http4k.contract.openapi.Render
import org.http4k.contract.openapi.RenderModes
import org.http4k.contract.openapi.SecurityRenderer
import org.http4k.contract.openapi.rendererFor
import org.http4k.contract.openapi.v3.renderer
import org.http4k.security.ApiKeySecurity
import org.http4k.security.AuthCodeOAuthSecurity
import org.http4k.security.BasicAuthSecurity
import org.http4k.security.BearerAuthSecurity
import org.http4k.security.ClientCredentialsOAuthSecurity
import org.http4k.security.ImplicitOAuthSecurity
import org.http4k.security.OpenIdConnectSecurity
import org.http4k.security.UserCredentialsOAuthSecurity

val OpenApi3SecurityRendererWithJwt: SecurityRenderer = SecurityRenderer(
    ApiKeySecurity.renderer,
    AuthCodeOAuthSecurity.renderer,
    BasicAuthSecurity.renderer,
    BearerAuthSecurity.renderer,
    ImplicitOAuthSecurity.renderer,
    UserCredentialsOAuthSecurity.renderer,
    OpenIdConnectSecurity.renderer,
    ClientCredentialsOAuthSecurity.renderer,
    JwtSecurity.renderer
)

val JwtSecurity.Companion.renderer
    get() = rendererFor<JwtSecurity> {
        object: RenderModes {
            override fun <NODE> full(): Render<NODE> = {
                obj(it.name to obj(
                    "scheme" to string("bearer"),
                    "type" to string("http")
                ))
            }

            override fun <NODE> ref(): Render<NODE> = { obj(it.name to array(emptyList())) }
        }
    }