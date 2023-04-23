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


class WalletApi(
    private val getRequestObject: GetRequestObject,
    private val getPresentationDefinition: GetPresentationDefinition
) {


    val route = coRouter {
        GET(requestJwtPath, this@WalletApi::handleGetRequestObject)
        GET(presentationDefinitionPath, this@WalletApi::handleGetPresentationDefinition)
    }

    private suspend fun handleGetRequestObject(req: ServerRequest): ServerResponse {


        suspend fun requestObjectFound(jwt: String) = ok().contentType(requestJwtMediaType).bodyValueAndAwait(jwt)

        val requestId = req.requestId()

        return when (val result = getRequestObject(requestId)) {
            is Found -> requestObjectFound(result.value)
            is NotFound -> notFound().buildAndAwait()
            is InvalidState -> badRequest().buildAndAwait()
        }
    }


    private suspend fun handleGetPresentationDefinition(req: ServerRequest): ServerResponse {
        suspend fun pdFound(pd: PresentationDefinition) = ok().json().bodyValueAndAwait(pd)
        val requestId = req.requestId()
        return when (val result = getPresentationDefinition(requestId)) {
            is NotFound -> notFound().buildAndAwait()
            is InvalidState -> badRequest().buildAndAwait()
            is Found -> pdFound(result.value)
        }

    }

    private fun ServerRequest.requestId() = RequestId(pathVariable("requestId"))

    companion object {
        val requestJwtMediaType = MediaType.parseMediaType("application/oauth-authz-req+jwt")
        const val requestJwtPath = "/wallet/request.jwt/{requestId}"

        fun requestJwtUrlBuilder(baseUrl: String): EmbedOption.ByReference<RequestId> =
            EmbedOption.byReference { requestId ->
                DefaultUriBuilderFactory(baseUrl)
                    .uriString(requestJwtPath)
                    .build(requestId.value).toURL()
            }

        const val presentationDefinitionPath = "/wallet/pd/{requestId}"

        fun presentationDefinitionUrlBuilder(baseUrl: String): EmbedOption.ByReference<RequestId> =
            EmbedOption.byReference { requestId ->
                DefaultUriBuilderFactory(baseUrl)
                    .uriString(presentationDefinitionPath)
                    .build(requestId.value).toURL()
            }
    }
}



