package eu.europa.ec.euidw.verifier.adapter.`in`.web

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.prex.PresentationExchange
import eu.europa.ec.euidw.verifier.application.port.`in`.*
import eu.europa.ec.euidw.verifier.application.port.`in`.QueryResponse.*
import eu.europa.ec.euidw.verifier.domain.EmbedOption
import eu.europa.ec.euidw.verifier.domain.RequestId
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
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
    private val rsaKey: RSAKey
) {

    private val logger : Logger = LoggerFactory.getLogger(WalletApi::class.java)

    /**
     * The routes available to the wallet
     */
    val route = coRouter {
        GET(requestJwtPath, this@WalletApi::handleGetRequestObject)
        GET(presentationDefinitionPath, this@WalletApi::handleGetPresentationDefinition)
        POST(walletResponsePath,
            //accept(MediaType.APPLICATION_FORM_URLENCODED),
            this@WalletApi::handlePostWalletResponse)
        GET(getPublicJwkSetPath) { _-> handleGetPublicJwkSet() }
    }

    /**
     * Handles a request placed by the wallet, in order to obtain
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
     * Handles a request placed by wallet, in order to obtain
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
     * Handles a POST request placed by the wallet, in order to submit
     * the [AuthorisationResponse], containing the id_token, presentation_submission
     * and the verifiableCredentials
     */
    private suspend fun handlePostWalletResponse(req: ServerRequest): ServerResponse {

        suspend fun walletResponseStored() = ok().buildAndAwait()

        suspend fun notFound() = ServerResponse.notFound().buildAndAwait()

        suspend fun failed() = badRequest().buildAndAwait()

        val formData = req.formData().awaitSingle().also {
            // debug
            logger.info("formData: $it")
        }
//        val vpToken = formData.getFirst("vpToken")
//        val vpTokenJson = Json.parseToJsonElement(vpToken!!)

        val input = AuthorisationResponseTO(
            idToken = formData.getFirst("idToken"),
            state = formData.getFirst("state")!!,
            vpToken = formData.getFirst("vpToken")?.let { Json.parseToJsonElement(it).jsonObject},
            presentationSubmission = formData.getFirst("vpToken")?.let { PresentationExchange.jsonParser.decodePresentationSubmission(it).getOrThrow()}
        )

//        val input = req.awaitBody<AuthorisationResponseTO>().also {
//            // debug
//            logger.info("input: $it")
//        }

        return when (postWalletResponse(input)) {
            is Found -> walletResponseStored()
            is NotFound -> notFound()
            else -> failed()
        }
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
         * Extracts from the request the [RequestId]
         */
        private fun ServerRequest.requestId() = RequestId(pathVariable("requestId"))

        fun requestJwtByReference(baseUrl: String): EmbedOption.ByReference<RequestId> =
            urlBuilder(baseUrl = baseUrl, pathTemplate = requestJwtPath)

        fun presentationDefinitionByReference(baseUrl: String): EmbedOption.ByReference<RequestId> =
            urlBuilder(baseUrl = baseUrl, pathTemplate = presentationDefinitionPath)

        fun publicJwkSet(baseUrl: String): EmbedOption.ByReference<Any> = EmbedOption.ByReference{ _ ->
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

        private fun urlBuilder(
            baseUrl: String,
            pathTemplate: String
        ) = EmbedOption.byReference<RequestId> { requestId ->
            DefaultUriBuilderFactory(baseUrl)
                .uriString(pathTemplate)
                .build(requestId.value)
                .toURL()
        }
    }
}



