package dev.andrewohara.http4k.filter

import dev.andrewohara.http4k.security.jwt.JwtAuthorizer
import org.http4k.filter.ServerFilters
import org.http4k.lens.RequestLens

/**
 * Authorize requests containing a valid JWT as a Bearer token
 */
fun ServerFilters.JwtAuth(authorizer: JwtAuthorizer<*>) =
    ServerFilters.BearerAuth { authorizer(it) != null }

/**
 * Populate the request context for requests containing a valid JWT as a Bearer Token.
 */
fun <Principal: Any> ServerFilters.JwtAuth(
    authorizer: JwtAuthorizer<Principal>,
    principal: RequestLens<Principal>,
) = ServerFilters.BearerAuth(principal, authorizer)