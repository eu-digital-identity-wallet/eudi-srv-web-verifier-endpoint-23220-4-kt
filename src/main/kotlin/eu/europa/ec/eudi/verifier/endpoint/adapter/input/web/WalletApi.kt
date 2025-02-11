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

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationExchange
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationRelatedUrlBuilder
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.QueryResponse.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.*
import org.springframework.web.util.DefaultUriBuilderFactory

/**
 * The WEB API available to the wallet
 */
class WalletApi(
    private val getRequestObject: GetRequestObject,
    private val getPresentationDefinition: GetPresentationDefinition,
    private val postWalletResponse: PostWalletResponse,
    private val getJarmJwks: GetJarmJwks,
    private val signingKey: JWK,
) {

    private val logger: Logger = LoggerFactory.getLogger(WalletApi::class.java)

    /**
     * The routes available to the wallet
     */
    val route = coRouter {
        GET(REQUEST_JWT_PATH, this@WalletApi::handleGetRequestObject)
        GET(PRESENTATION_DEFINITION_PATH, this@WalletApi::handleGetPresentationDefinition)
        POST(
            WALLET_RESPONSE_PATH,
            this@WalletApi::handlePostWalletResponse,
        )
        GET(GET_PUBLIC_JWK_SET_PATH) { _ -> handleGetPublicJwkSet() }
        GET(JARM_JWK_SET_PATH, this@WalletApi::handleGetJarmJwks)
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
        logger.info("Handling GetRequestObject for ${requestId.value} ...")
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
        logger.info("Handling GetPresentationDefinition for ${requestId.value} ...")

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
    private suspend fun handlePostWalletResponse(req: ServerRequest): ServerResponse = try {
        logger.info("Handling PostWalletResponse ...")
        val requestId = req.requestId()
        val walletResponse = req.awaitFormData().walletResponse()
        postWalletResponse(requestId, walletResponse).fold(
            ifRight = { response ->
                logger.info("PostWalletResponse processed")
                if (response == null) {
                    logger.info("Verifier UI will poll for Wallet Response")
                    ok().json().bodyValueAndAwait(JsonObject(emptyMap()))
                } else {
                    logger.info("Wallet must redirect to ${response.redirectUri}")
                    ok().json().bodyValueAndAwait(response)
                }
            },
            ifLeft = { error ->
                logger.error("$error while handling post of wallet response ")
                badRequest().buildAndAwait()
            },
        )
    } catch (t: SerializationException) {
        logger.error("While handling post of wallet response failed to decode JSON", t)
        badRequest().buildAndAwait()
    }

    private suspend fun handleGetPublicJwkSet(): ServerResponse {
        logger.info("Handling GetPublicJwkSet ...")
        val publicJwkSet = JWKSet(signingKey).toJSONObject(true)
        return ok()
            .contentType(MediaType.parseMediaType(JWKSet.MIME_TYPE))
            .bodyValueAndAwait(publicJwkSet)
    }

    /**
     * Handles the GET request for fetching the JWKS to be used for JARM.
     */
    private suspend fun handleGetJarmJwks(request: ServerRequest): ServerResponse {
        val requestId = request.requestId().also { logger.info("Handling GetJarmJwks for ${it.value}...") }
        return when (val queryResponse = getJarmJwks(requestId)) {
            is NotFound -> notFound().buildAndAwait()
            is InvalidState -> badRequest().buildAndAwait()
            is Found -> ok()
                .contentType(MediaType.parseMediaType(JWKSet.MIME_TYPE))
                .bodyValueAndAwait(queryResponse.value.toJSONObject(true))
        }
    }

    companion object {
        const val GET_PUBLIC_JWK_SET_PATH = "/wallet/public-keys.json"

        /**
         * Path template for the route for
         * getting the presentation's request object
         */
        const val REQUEST_JWT_PATH = "/wallet/request.jwt/{requestId}"

        /**
         * Path template for the route for
         * getting the presentation definition
         */
        const val PRESENTATION_DEFINITION_PATH = "/wallet/pd/{requestId}"

        /**
         * Path template for the route for getting the JWKS that contains the Ephemeral Key for JARM.
         */
        const val JARM_JWK_SET_PATH = "/wallet/jarm/{requestId}/jwks.json"

        /**
         * Path template for the route for
         * posting the Authorisation Response
         */
        const val WALLET_RESPONSE_PATH = "/wallet/direct_post/{requestId}"

        /**
         * Extracts from the request the [RequestId]
         */
        private fun ServerRequest.requestId() = RequestId(pathVariable("requestId"))

        private fun MultiValueMap<String, String>.walletResponse(): AuthorisationResponse {
            fun directPost(): AuthorisationResponse.DirectPost {
                fun String.toJsonElement(): JsonElement =
                    runCatching {
                        Json.decodeFromString<JsonElement>(this)
                    }.getOrElse { JsonPrimitive(this) }

                return AuthorisationResponseTO(
                    state = getFirst("state"),
                    idToken = getFirst("id_token"),
                    vpToken = getFirst("vp_token")?.toJsonElement(),
                    presentationSubmission = getFirst("presentation_submission")?.let {
                        PresentationExchange.jsonParser.decodePresentationSubmission(it).getOrThrow()
                    },
                    error = getFirst("error"),
                    errorDescription = getFirst("error_description"),
                ).run { AuthorisationResponse.DirectPost(this) }
            }

            fun directPostJwt() = getFirst("response")?.let { jwt ->
                AuthorisationResponse.DirectPostJwt(jwt)
            }

            return directPostJwt() ?: directPost()
        }

        fun requestJwtByReference(baseUrl: String): EmbedOption.ByReference<RequestId> =
            urlBuilder(baseUrl = baseUrl, pathTemplate = REQUEST_JWT_PATH)

        fun presentationDefinitionByReference(baseUrl: String): EmbedOption.ByReference<RequestId> =
            urlBuilder(baseUrl = baseUrl, pathTemplate = PRESENTATION_DEFINITION_PATH)

        fun publicJwkSet(baseUrl: String): EmbedOption.ByReference<Any> = EmbedOption.ByReference { _ ->
            DefaultUriBuilderFactory(baseUrl)
                .uriString(GET_PUBLIC_JWK_SET_PATH)
                .build()
                .toURL()
        }

        fun jarmJwksByReference(baseUrl: String): EmbedOption.ByReference<RequestId> =
            urlBuilder(baseUrl, JARM_JWK_SET_PATH)

        fun directPost(baseUrl: String): PresentationRelatedUrlBuilder<RequestId> = {
            DefaultUriBuilderFactory(baseUrl)
                .uriString(WALLET_RESPONSE_PATH)
                .build(it.value)
                .toURL()
        }

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
