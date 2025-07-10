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

import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseCode
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import kotlinx.serialization.SerializationException
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.CacheControl
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.http.MediaType.IMAGE_PNG
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.*
import kotlin.jvm.optionals.getOrNull

internal class VerifierApi(
    private val initTransaction: InitTransaction,
    private val getWalletResponse: GetWalletResponse,
    private val getClientMetadata: GetClientMetadata,
) {

    private val logger: Logger = LoggerFactory.getLogger(VerifierApi::class.java)
    val route = coRouter {

        POST(
            INIT_TRANSACTION_PATH,
            contentType(APPLICATION_JSON) and accept(APPLICATION_JSON, IMAGE_PNG),
            ::handleInitTransaction,
        )
        GET(WALLET_RESPONSE_PATH, accept(APPLICATION_JSON), this@VerifierApi::handleGetWalletResponse)
        GET(CLIENT_METADATA_PATH, accept(APPLICATION_JSON), this@VerifierApi::handleGetClientMetadata)
    }

    private suspend fun handleInitTransaction(req: ServerRequest): ServerResponse = try {
        val accept = req.headers().accept()
        val output = when {
            IMAGE_PNG in accept -> Output.QrCode
            else -> Output.Json
        }
        val input = req.awaitBody<InitTransactionTO>().copy(output = output)

        logger.info("Handling InitTransaction nonce=${input.nonce} ... ")
        initTransaction(input).fold(
            ifRight = {
                when (it) {
                    is InitTransactionResponse.JwtSecuredAuthorizationRequestTO -> {
                        logger.info("Initiated transaction tx ${it.transactionId}")
                        ok().json().bodyValueAndAwait(it)
                    }
                    is InitTransactionResponse.QrCode -> {
                        logger.info("Initiated transaction with qr image")
                        ok().contentType(IMAGE_PNG).bodyValueAndAwait(it.qrCode)
                    }
                }
            },
            ifLeft = { it.asBadRequest() },
        )
    } catch (t: SerializationException) {
        logger.warn("While handling InitTransaction", t)
        badRequest().buildAndAwait()
    }

    /**
     * Handles a request placed by verifier, input order to obtain
     * the wallet authorization response
     */
    private suspend fun handleGetWalletResponse(req: ServerRequest): ServerResponse {
        suspend fun found(walletResponse: WalletResponseTO) = ok().json().bodyValueAndAwait(walletResponse)

        val transactionId = req.transactionId()
        val responseCode = req.queryParam("response_code").getOrNull()?.let { ResponseCode(it) }

        logger.info("Handling GetWalletResponse for tx ${transactionId.value} and response_code: ${responseCode?.value ?: "n/a"}. ...")
        return when (val result = getWalletResponse(transactionId, responseCode)) {
            is QueryResponse.NotFound -> notFound().buildAndAwait()
            is QueryResponse.InvalidState -> badRequest().buildAndAwait()
            is QueryResponse.Found -> found(result.value)
        }
    }

    private suspend fun handleGetClientMetadata(req: ServerRequest): ServerResponse =
        ok().json()
            .cacheControl(CacheControl.noStore())
            .bodyValueAndAwait(getClientMetadata())

    companion object {
        const val INIT_TRANSACTION_PATH = "/ui/presentations"
        const val WALLET_RESPONSE_PATH = "/ui/presentations/{transactionId}"
        const val EVENTS_RESPONSE_PATH = "/ui/presentations/{transactionId}/events"
        const val CLIENT_METADATA_PATH = "/ui/clientMetadata"

        /**
         * Extracts from the request the [RequestId]
         */
        private fun ServerRequest.transactionId() = TransactionId(pathVariable("transactionId"))
        private suspend fun ValidationError.asBadRequest() =
            badRequest().json().bodyValueAndAwait(mapOf("error" to this))
    }
}
