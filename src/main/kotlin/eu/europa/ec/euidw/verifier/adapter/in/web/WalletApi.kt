package eu.europa.ec.euidw.verifier.adapter.`in`.web

import eu.europa.ec.euidw.verifier.application.port.`in`.GetPresentationDefinition
import eu.europa.ec.euidw.verifier.application.port.`in`.GetRequestObject
import eu.europa.ec.euidw.verifier.application.port.`in`.QueryResponse.*
import eu.europa.ec.euidw.verifier.domain.RequestId
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.*
import org.springframework.web.util.DefaultUriBuilderFactory
import java.net.URL


class WalletApi(
    private val getRequestObject: GetRequestObject,
    private val getPresentationDefinition: GetPresentationDefinition
) {


    val route = coRouter {
        GET(requestJwtPath, this@WalletApi::handleGetRequestObject)
        GET(presentationDefinitionPath, this@WalletApi::handleGetPresentationDefinition)
    }

    suspend fun handleGetRequestObject(req: ServerRequest): ServerResponse {


        suspend fun requestObjectFound(jwt: String) =
            ok()
                .contentType(MediaType.TEXT_PLAIN)
                //.contentType(MediaType.parseMediaType("application/oauth-authz-req+jwt"))
                .bodyValueAndAwait(jwt)

        val requestId = req.requestId()

        return when (val result = getRequestObject(requestId)) {
            is Found -> requestObjectFound(result.value)
            is NotFound -> notFound().buildAndAwait()
            is InvalidState -> badRequest().buildAndAwait()
        }
    }


    suspend fun handleGetPresentationDefinition(req: ServerRequest): ServerResponse {
        suspend fun pdFound(json: String) = ok().json().bodyValueAndAwait(json)
        val requestId = req.requestId()
        return when (val result = getPresentationDefinition(requestId)) {
            is NotFound -> notFound().buildAndAwait()
            is InvalidState -> badRequest().buildAndAwait()
            is Found -> pdFound(result.value)
        }

    }

    private fun ServerRequest.requestId() = RequestId(pathVariable("requestId"))

    companion object {
        const val requestJwtPath = "/wallet/request.jwt/{requestId}"

        fun requestJwtUrlBuilder(baseUrl: String): (RequestId) -> URL = { requestId ->
            DefaultUriBuilderFactory(baseUrl)
                .uriString(requestJwtPath)
                .build(requestId.value).toURL()
        }

        const val presentationDefinitionPath = "/wallet/pd/{requestId}"

        fun presentationDefinitionUrlBuilder(baseUrl: String): (RequestId) -> URL = { requestId ->
            DefaultUriBuilderFactory(baseUrl)
                .uriString(presentationDefinitionPath)
                .build(requestId.value).toURL()
        }
    }
}



