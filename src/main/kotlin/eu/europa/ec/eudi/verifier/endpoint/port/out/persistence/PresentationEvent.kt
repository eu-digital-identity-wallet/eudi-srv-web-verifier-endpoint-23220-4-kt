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
package eu.europa.ec.eudi.verifier.endpoint.port.out.persistence

import eu.europa.ec.eudi.statium.StatusReference
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.serializer.InstantSerializer
import eu.europa.ec.eudi.verifier.endpoint.domain.Jwt
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseAcceptedTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError
import kotlinx.serialization.Serializable
import java.time.Instant

@Serializable
sealed interface PresentationEvent {
    val transactionId: TransactionId

    @Serializable(with = InstantSerializer::class)
    val timestamp: Instant

    @Serializable
    data class TransactionInitialized(
        override val transactionId: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val timestamp: Instant,
        val response: InitTransactionResponse.JwtSecuredAuthorizationRequestTO,
    ) : PresentationEvent

    @Serializable
    data class RequestObjectRetrieved(
        override val transactionId: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val timestamp: Instant,
        val jwt: Jwt,
    ) : PresentationEvent

    @Serializable
    data class FailedToRetrieveRequestObject(
        override val transactionId: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val timestamp: Instant,
        val cause: String,
    ) : PresentationEvent

    @Serializable
    data class FailedToRetrievePresentationDefinition(
        override val transactionId: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val timestamp: Instant,
        val cause: String,
    ) : PresentationEvent

    @Serializable
    data class WalletResponsePosted(
        override val transactionId: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val timestamp: Instant,
        val walletResponse: WalletResponseTO,
        val verifierEndpointResponse: WalletResponseAcceptedTO?,
    ) : PresentationEvent

    @Serializable
    data class WalletFailedToPostResponse(
        override val transactionId: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val timestamp: Instant,
        val cause: WalletResponseValidationError,
    ) : PresentationEvent

    @Serializable
    data class VerifierGotWalletResponse(
        override val transactionId: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val timestamp: Instant,
        val walletResponse: WalletResponseTO,
    ) : PresentationEvent

    @Serializable
    data class VerifierFailedToGetWalletResponse(
        override val transactionId: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val timestamp: Instant,
        val cause: String,
    ) : PresentationEvent

    @Serializable
    data class PresentationExpired(
        override val transactionId: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val timestamp: Instant,
    ) : PresentationEvent

    @Serializable
    data class AttestationStatusCheckSuccessful(
        override val transactionId: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val timestamp: Instant,
        val statusReference: StatusReference,
    ) : PresentationEvent

    @Serializable
    data class AttestationStatusCheckFailed(
        override val transactionId: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val timestamp: Instant,
        val statusReference: StatusReference?,
        val cause: String?,
    ) : PresentationEvent
}
