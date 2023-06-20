/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationExchange
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.QueryResponse.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.*
import org.springframework.web.util.DefaultUriBuilderFactory
import java.net.URL

/**
 * The WEB API available to the wallet
 */
class WalletApi(
    private val getRequestObject: GetRequestObject,
    private val getPresentationDefinition: GetPresentationDefinition,
    private val postWalletResponse: PostWalletResponse,
    private val rsaKey: RSAKey,
) {

    private val logger: Logger = LoggerFactory.getLogger(WalletApi::class.java)

    /**
     * The routes available to the wallet
     */
    val route = coRouter {
        GET(requestJwtPath, this@WalletApi::handleGetRequestObject)
        GET(presentationDefinitionPath, this@WalletApi::handleGetPresentationDefinition)
        POST(
            walletResponsePath,
            this@WalletApi::handlePostWalletResponse,
        )
        POST(
            walletJwtResponsePath,
            this@WalletApi::handlePostWalletJwtResponse,
        )
        GET(getPublicJwkSetPath) { _ -> handleGetPublicJwkSet() }
    }

    /**
     * Handles a request placed by the wallet, input order to obtain
     * the Request Object of the presentation.
     * If found, the Request Object will be returned as JWT
     */
    private suspend fun handleGetRequestObject(req: ServerRequest): ServerResponse {
        suspend fun requestObjectFound(jwt: String) =
            ok().contentType(MediaType.parseMediaType("application/oauth-authz-req+jwt"))
                .bodyValueAndAwait(jwt)

        val requestId = req.requestId()

        return when (val result = getRequestObject(requestId)) {
            is Found -> requestObjectFound(result.value)
            is NotFound -> notFound().buildAndAwait()
            is InvalidState -> badRequest().buildAndAwait()
        }
    }

    /**
     * Handles a request placed by wallet, input order to obtain
     * the [PresentationDefinition] of the presentation
     */
    private suspend fun handleGetPresentationDefinition(req: ServerRequest): ServerResponse {
        suspend fun pdFound(pd: PresentationDefinition) = ok().json().bodyValueAndAwait(pd)

        val requestId = req.requestId()

        return when (val result = getPresentationDefinition(requestId)) {
            is NotFound -> notFound().buildAndAwait()
            is InvalidState -> badRequest().buildAndAwait()
            is Found -> pdFound(result.value)
        }
    }

    /**
     * Handles a POST request placed by the wallet, input order to submit
     * the [AuthorisationResponse], containing the id_token, presentation_submission
     * and the verifiableCredentials
     */
    private suspend fun handlePostWalletResponse(req: ServerRequest): ServerResponse {
        suspend fun walletResponseStored() = ok().buildAndAwait()

        suspend fun notFound() = ServerResponse.notFound().buildAndAwait()

        suspend fun failed() = badRequest().buildAndAwait()

        val input = with(req.awaitFormData()) {
            logger.info("formData: $this")
            AuthorisationResponseTO(
                state = getFirst("state"),
                idToken = getFirst("id_token"),
                vpToken = getFirst("vp_token"),
                presentationSubmission = getFirst("presentation_submission")?.let {
                    PresentationExchange.jsonParser.decodePresentationSubmission(it).getOrThrow()
                },
                error = getFirst("error"),
                errorDescription = getFirst("error_description"),
            )
        }

        return when (postWalletResponse(input)) {
            is Found -> walletResponseStored()
            is NotFound -> notFound()
            else -> failed()
        }
    }

    /**
     * Handles a POST request placed by the wallet, input order to submit
     * the [AuthorisationResponse], containing the id_token, presentation_submission
     * and the verifiableCredentials
     */
    private suspend fun handlePostWalletJwtResponse(req: ServerRequest): ServerResponse {
        suspend fun walletResponseStored() = ok().buildAndAwait()

        suspend fun notFound() = ServerResponse.notFound().buildAndAwait()

        suspend fun failed() = badRequest().buildAndAwait()

        val input = with(req.awaitFormData()) {
            logger.info("post body: $this")
            // process the form data
            var response = getFirst("response")
            println("response: $response")

            processJwt(response!!)
        }

        return input.fold(
            onSuccess = {
                when (postWalletResponse(it)) {
                    is Found -> walletResponseStored()
                    is NotFound -> notFound()
                    else -> failed()
                }
            },
            onFailure = { failed() },
        )
    }

    private suspend fun processJwt(jwt: String): Result<AuthorisationResponseTO> = runCatching {
        var decodedJwt = SignedJWT.parse(jwt)
        println("header:\n${decodedJwt.header}")

        // get AuthorisationResponseTO from claimSet
        mapToDomain(decodedJwt.jwtClaimsSet)
    }

    private fun mapToDomain(claimSet: JWTClaimsSet): AuthorisationResponseTO = runBlocking {
        AuthorisationResponseTO(
            state = claimSet.getClaim("state")?.toString(),
            idToken = claimSet.getClaim("id_token")?.toString(),
            vpToken = claimSet.getClaim("vp_token")?.toString(),
            presentationSubmission = claimSet.getClaim("presentation_submission")?.let {
                PresentationExchange.jsonParser.decodePresentationSubmission(it.toString()).getOrThrow()
            },
            error = claimSet.getClaim("error")?.toString(),
            errorDescription = claimSet.getClaim("error_description")?.toString(),
        )
    }

    private suspend fun handleGetPublicJwkSet(): ServerResponse {
        val publicJwkSet = JWKSet(rsaKey).toJSONObject(true)
        return ok()
            .contentType(MediaType.parseMediaType(JWKSet.MIME_TYPE))
            .bodyValueAndAwait(publicJwkSet)
    }

    companion object {
        const val getPublicJwkSetPath = "/wallet/public-keys.json"

        /**
         * Path template for the route for
         * getting the presentation's request object
         */
        const val requestJwtPath = "/wallet/request.jwt/{requestId}"

        /**
         * Path template for the route for
         * getting the presentation definition
         */
        const val presentationDefinitionPath = "/wallet/pd/{requestId}"

        /**
         * Path template for the route for
         * posting the Authorisation Response
         */
        const val walletResponsePath = "/wallet/direct_post"

        /**
         * Path template for the route for
         * posting the Authorisation Response as JWT
         * (response mode: "direct_post.jwt")
         *
         */
        const val walletJwtResponsePath = "/wallet/direct_post.jwt"

        /**
         * Extracts from the request the [RequestId]
         */
        private fun ServerRequest.requestId() = RequestId(pathVariable("requestId"))

        fun requestJwtByReference(baseUrl: String): EmbedOption.ByReference<RequestId> =
            urlBuilder(baseUrl = baseUrl, pathTemplate = requestJwtPath)

        fun presentationDefinitionByReference(baseUrl: String): EmbedOption.ByReference<RequestId> =
            urlBuilder(baseUrl = baseUrl, pathTemplate = presentationDefinitionPath)

        fun publicJwkSet(baseUrl: String): EmbedOption.ByReference<Any> = EmbedOption.ByReference { _ ->
            DefaultUriBuilderFactory(baseUrl)
                .uriString(getPublicJwkSetPath)
                .build()
                .toURL()
        }

        fun directPost(baseUrl: String): URL =
            DefaultUriBuilderFactory(baseUrl)
                .uriString(walletResponsePath)
                .build()
                .toURL()

        fun directPostJwt(baseUrl: String): URL =
            DefaultUriBuilderFactory(baseUrl)
                .uriString(walletJwtResponsePath)
                .build()
                .toURL()

        private fun urlBuilder(
            baseUrl: String,
            pathTemplate: String,
        ) = EmbedOption.byReference<RequestId> { requestId ->
            DefaultUriBuilderFactory(baseUrl)
                .uriString(pathTemplate)
                .build(requestId.value)
                .toURL()
        }
    }
}
