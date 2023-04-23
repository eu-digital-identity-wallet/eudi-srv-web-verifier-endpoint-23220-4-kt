package eu.europa.ec.euidw.verifier.adapter.`in`.web

import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.verifier.application.port.`in`.GetPresentationDefinition
import eu.europa.ec.euidw.verifier.application.port.`in`.GetRequestObject
import eu.europa.ec.euidw.verifier.application.port.`in`.QueryResponse.*
import eu.europa.ec.euidw.verifier.domain.EmbedOption
import eu.europa.ec.euidw.verifier.domain.RequestId
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.*
import org.springframework.web.util.DefaultUriBuilderFactory

/**
 * The WEB API available to the wallet
 */
class WalletApi(
    private val getRequestObject: GetRequestObject,
    private val getPresentationDefinition: GetPresentationDefinition
) {

    /**
     * The routes available to the wallet
     */
    val route = coRouter {
        GET(requestJwtPath, this@WalletApi::handleGetRequestObject)
        GET(presentationDefinitionPath, this@WalletApi::handleGetPresentationDefinition)
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

    companion object {
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
         * Extracts from the request the [RequestId]
         */
        private fun ServerRequest.requestId() = RequestId(pathVariable("requestId"))

        fun requestJwtByReference(baseUrl: String): EmbedOption.ByReference<RequestId> =
            urlBuilder(baseUrl = baseUrl, pathTemplate = requestJwtPath)

        fun presentationDefinitionByReference(baseUrl: String): EmbedOption.ByReference<RequestId> =
            urlBuilder(baseUrl = baseUrl, pathTemplate = presentationDefinitionPath)

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



