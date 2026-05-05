package dev.andrewohara.http4k.openapi.v3

import dev.andrewohara.http4k.filter.JwtAuth
import dev.andrewohara.http4k.security.jwt.JwtAuthorizer
import org.http4k.core.Filter
import org.http4k.filter.ServerFilters
import org.http4k.lens.RequestLens
import org.http4k.security.Security

/**
 * Checks for the presence of and verifies JWT credentials. Filter returns 401 if auth fails.
 */
class JwtSecurity(override val filter: Filter, val name: String = "jwtAuth") : Security {
    constructor(authorizer: JwtAuthorizer<*>, name: String = "jwtAuth") : this(ServerFilters.JwtAuth(authorizer), name)

    companion object {
        operator fun <Principal: Any> invoke(authorizer: JwtAuthorizer<Principal>, key: RequestLens<Principal>, name: String = "jwtAuth") =
            JwtSecurity(ServerFilters.JwtAuth(authorizer, key), name)
    }
}