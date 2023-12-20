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

import arrow.core.raise.either
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationId
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.badRequest
import org.springframework.web.reactive.function.server.ServerResponse.ok
import kotlin.jvm.optionals.getOrNull

class VerifierApi(
    private val initTransaction: InitTransaction,
    private val getWalletResponse: GetWalletResponse,
) {

    val route = coRouter {

        POST(
            initTransactionPath,
            contentType(APPLICATION_JSON) and accept(APPLICATION_JSON),
            this@VerifierApi::handleInitTransaction,
        )
        GET(walletResponsePath, accept(APPLICATION_JSON), this@VerifierApi::handleGetWalletResponse)
    }

    private suspend fun handleInitTransaction(req: ServerRequest): ServerResponse {
        suspend fun transactionInitiated(jar: JwtSecuredAuthorizationRequestTO) =
            ok().json().bodyValueAndAwait(jar)

        suspend fun failed(e: ValidationError) = e.asBadRequest()

        val input = req.awaitBody<InitTransactionTO>()

        return either { initTransaction(input) }.fold(
            ifRight = { transactionInitiated(it) },
            ifLeft = { failed(it) },
        )
    }

    /**
     * Handles a request placed by verifier, input order to obtain
     * the wallet authorisation response
     */
    private suspend fun handleGetWalletResponse(req: ServerRequest): ServerResponse {
        suspend fun found(walletResponse: WalletResponseTO) = ok().json().bodyValueAndAwait(walletResponse)

        val presentationId = req.presentationId()
        val nonce = req.queryParam("nonce").getOrNull()?.let { Nonce(it) }

        return if (nonce == null) {
            ValidationError.MissingNonce.asBadRequest()
        } else {
            when (val result = getWalletResponse(presentationId, nonce)) {
                is QueryResponse.NotFound -> ServerResponse.notFound().buildAndAwait()
                is QueryResponse.InvalidState -> badRequest().buildAndAwait()
                is QueryResponse.Found -> found(result.value)
            }
        }
    }

    companion object {
        const val initTransactionPath = "/ui/presentations"
        const val walletResponsePath = "/ui/presentations/{presentationId}"

        /**
         * Extracts from the request the [RequestId]
         */
        private fun ServerRequest.presentationId() = PresentationId(pathVariable("presentationId"))
        private suspend fun ValidationError.asBadRequest() =
            badRequest().json().bodyValueAndAwait(mapOf("error" to this))
    }
}
