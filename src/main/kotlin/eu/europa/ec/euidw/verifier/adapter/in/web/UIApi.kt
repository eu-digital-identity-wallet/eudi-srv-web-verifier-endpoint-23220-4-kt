package eu.europa.ec.euidw.verifier.adapter.`in`.web

import eu.europa.ec.euidw.verifier.application.port.`in`.InitTransaction
import eu.europa.ec.euidw.verifier.application.port.`in`.InitTransactionTO
import eu.europa.ec.euidw.verifier.application.port.`in`.JwtSecuredAuthorizationRequestTO
import eu.europa.ec.euidw.verifier.application.port.`in`.ValidationException
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.badRequest
import org.springframework.web.reactive.function.server.ServerResponse.ok

class UIApi(private val initTransaction: InitTransaction) {


    val route = coRouter {
        "/ui/presentations".nest {
            POST("", contentType(APPLICATION_JSON) and accept(APPLICATION_JSON), this@UIApi::handleInitTransaction)
        }
    }

    private suspend fun handleInitTransaction(req: ServerRequest): ServerResponse {

        suspend fun transactionInitiated(jar: JwtSecuredAuthorizationRequestTO) =
            ok().json().bodyValueAndAwait(jar)

        suspend fun failed(t: Throwable) = when (t) {
            is ValidationException -> badRequest().json().bodyValueAndAwait("error" to t.error)
            else -> badRequest().buildAndAwait()
        }

        val input = req.awaitBody<InitTransactionTO>()

        return initTransaction(input).fold(
            onSuccess = { transactionInitiated(it) },
            onFailure = { failed(it) }
        )
    }

}