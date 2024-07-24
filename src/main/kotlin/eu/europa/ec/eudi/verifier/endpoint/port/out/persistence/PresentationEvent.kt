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

import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.verifier.endpoint.domain.Jwt
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.input.JwtSecuredAuthorizationRequestTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseAcceptedTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import java.time.Instant

sealed interface PresentationEvent {
    val transactionId: TransactionId
    val timestamp: Instant

    data class TransactionInitialized(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val response: JwtSecuredAuthorizationRequestTO,
    ) : PresentationEvent

    data class RequestObjectRetrieved(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val jwt: Jwt,
    ) : PresentationEvent

    data class PresentationDefinitionRetrieved(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val presentationDefinition: PresentationDefinition,
    ) : PresentationEvent

    data class WalletResponsePosted(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val walletResponse: WalletResponseTO,
        val verifierResponse: WalletResponseAcceptedTO?,
    ) : PresentationEvent

    data class VerifierGotWalletResponse(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
        val walletResponse: WalletResponseTO,
    ) : PresentationEvent

    data class PresentationExpired(
        override val transactionId: TransactionId,
        override val timestamp: Instant,
    ) : PresentationEvent
}
