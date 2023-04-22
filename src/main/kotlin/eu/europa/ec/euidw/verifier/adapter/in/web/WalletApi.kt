package eu.europa.ec.euidw.verifier.adapter.`in`.web

import eu.europa.ec.euidw.verifier.application.port.`in`.GetPresentationDefinition
import eu.europa.ec.euidw.verifier.application.port.`in`.GetRequestObject
import eu.europa.ec.euidw.verifier.application.port.`in`.QueryResponse.*
import eu.europa.ec.euidw.verifier.domain.RequestId
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.*


class WalletApi(
    private val getRequestObject: GetRequestObject,
    private val getPresentationDefinition: GetPresentationDefinition
) {


    val route = coRouter {
        "/wallet".nest {
            GET("/{requestId}/ro", this@WalletApi::handleGetRequestObject)
            GET("/{requestId}/pd", this@WalletApi::handleGetPresentationDefinition)
        }
    }

    suspend fun handleGetRequestObject(req: ServerRequest): ServerResponse {

        suspend fun requestObjectFound(jwt: String) = ok().contentType(APPLICATION_JSON).bodyValueAndAwait(jwt)
        val requestId = req.requestId()
        return when (val result = getRequestObject(requestId)) {
            is NotFound -> notFound().buildAndAwait()
            is InvalidState -> badRequest().buildAndAwait()
            is Found -> requestObjectFound(result.value)
        }
    }


    suspend fun handleGetPresentationDefinition(req: ServerRequest): ServerResponse {
        suspend fun pdFound(jwt: String) = ok().contentType(APPLICATION_JSON).bodyValueAndAwait(jwt)
        val requestId = req.requestId()
        return when (val result = getPresentationDefinition(requestId)) {
            is NotFound -> notFound().buildAndAwait()
            is InvalidState -> badRequest().buildAndAwait()
            is Found -> pdFound(result.value)
        }

    }

    private fun ServerRequest.requestId() = RequestId(pathVariable("requestId"))

}
