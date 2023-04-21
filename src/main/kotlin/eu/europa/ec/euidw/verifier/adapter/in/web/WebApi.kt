package eu.europa.ec.euidw.verifier.adapter.`in`.web

import eu.europa.ec.euidw.verifier.application.port.`in`.*
import eu.europa.ec.euidw.verifier.domain.PresentationId
import org.springframework.context.annotation.Bean
import org.springframework.http.MediaType
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.ok


class WebApi(
    private val initTransaction: InitTransaction,
    private val getRequestObject: GetRequestObject
) {



    val presentationRoute = coRouter {
        "/presentations/".nest {
            POST("", accept(MediaType.APPLICATION_JSON), this@WebApi::initTransactionHandler)
            GET("/{id}/requestObject", this@WebApi::getRequestObjectHandler)
        }
    }


    internal suspend fun initTransactionHandler(req: ServerRequest): ServerResponse {

        suspend fun parseInput() = req.awaitBodyOrNull(InitTransactionTO::class)

        suspend fun transactionInitiated(jar: JwtSecuredAuthorizationRequestTO) =
            ok().contentType(APPLICATION_JSON).bodyValueAndAwait(jar)

        return when (val input = parseInput()) {
            null -> badRequest()
            else -> initTransaction(input).fold(
                onSuccess = { transactionInitiated(it) },
                onFailure = { badRequest() }
            )
        }

    }

    internal suspend fun getRequestObjectHandler(req: ServerRequest): ServerResponse {

        fun parseId() = req.pathVariable("id").let { PresentationId.parse(it) }
        suspend fun requestObjectFound(jwt: String) = ok().contentType(APPLICATION_JSON).bodyValueAndAwait(jwt)

        return when (val presentationId = parseId()) {
            null -> badRequest()
            else -> when (val result = getRequestObject(presentationId)) {
                is QueryResponse.NotFound -> notFound()
                is QueryResponse.InvalidState -> badRequest()
                is QueryResponse.Found -> requestObjectFound(result.value)
            }
        }
    }

    private suspend fun notFound() = ServerResponse.notFound().buildAndAwait()
    private suspend fun badRequest() = ServerResponse.badRequest().buildAndAwait()
}
