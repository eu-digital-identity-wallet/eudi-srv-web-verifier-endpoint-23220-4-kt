package eu.europa.ec.euidw.verifier.adapter.`in`.web

import eu.europa.ec.euidw.verifier.application.port.`in`.InitTransaction
import eu.europa.ec.euidw.verifier.application.port.`in`.InitTransactionTO
import eu.europa.ec.euidw.verifier.application.port.`in`.JwtSecuredAuthorizationRequestTO
import org.springframework.http.MediaType
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.web.reactive.function.server.*

class UIApi(private val initTransaction: InitTransaction) {


    val route = coRouter {
        "/ui/presentations".nest {
            POST("", contentType(APPLICATION_JSON).and(accept(APPLICATION_JSON)), this@UIApi::handleInitTransaction)
        }
    }
    suspend fun handleInitTransaction(req: ServerRequest): ServerResponse {

        suspend fun parseInput() = req.awaitBodyOrNull(InitTransactionTO::class)

        suspend fun transactionInitiated(jar: JwtSecuredAuthorizationRequestTO) =
            ServerResponse.ok().contentType(APPLICATION_JSON).bodyValueAndAwait(jar)

        val input = parseInput()

        return when (input) {
            null -> ServerResponse.badRequest().buildAndAwait()
            else -> initTransaction(input).fold(
                onSuccess = { transactionInitiated(it) },
                onFailure = { ServerResponse.badRequest().buildAndAwait() }
            )
        }

    }

}