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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import eu.europa.ec.eudi.prex.PresentationSubmission
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.QueryResponse.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.time.Clock

/**
 * Represent the [WalletResponse] as returned by the wallet
 */
@Serializable
@SerialName("wallet_response")
data class WalletResponseTO(
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("vp_token") val vpToken: String? = null,
    @SerialName("presentation_submission") val presentationSubmission: PresentationSubmission? = null,
    @SerialName("error") val error: String? = null,
    @SerialName("error_description") val errorDescription: String? = null,
)

internal fun WalletResponse.toTO(): WalletResponseTO {
    return when (this) {
        is WalletResponse.IdToken -> WalletResponseTO(idToken = idToken)
        is WalletResponse.VpToken -> WalletResponseTO(
            vpToken = vpToken,
            presentationSubmission = presentationSubmission,
        )

        is WalletResponse.IdAndVpToken -> WalletResponseTO(
            idToken = idToken,
            vpToken = vpToken,
            presentationSubmission = presentationSubmission,
        )

        is WalletResponse.Error -> WalletResponseTO(
            error = value,
            errorDescription = description,
        )
    }
}

/**
 * Given a [TransactionId] and a [Nonce] returns the [WalletResponse]
 */
fun interface GetWalletResponse {
    suspend operator fun invoke(
        transactionId: TransactionId,
        responseCode: ResponseCode?,
    ): QueryResponse<WalletResponseTO>
}

class GetWalletResponseLive(
    private val clock: Clock,
    private val loadPresentationById: LoadPresentationById,
    private val publishPresentationEvent: PublishPresentationEvent,
) : GetWalletResponse {
    override suspend fun invoke(
        transactionId: TransactionId,
        responseCode: ResponseCode?,
    ): QueryResponse<WalletResponseTO> {
        return when (val presentation = loadPresentationById(transactionId)) {
            null -> NotFound
            is Presentation.Submitted -> {
                when {
                    presentation.responseCode != null && responseCode == null -> InvalidState
                    presentation.responseCode == null && responseCode != null -> InvalidState
                    presentation.responseCode == null && responseCode == null -> found(presentation)
                    presentation.responseCode == responseCode -> found(presentation)
                    else -> InvalidState
                }
            }

            else -> InvalidState
        }
    }

    suspend fun found(presentation: Presentation.Submitted): Found<WalletResponseTO> {
        val walletResponse = presentation.walletResponse.toTO()
        log(presentation, walletResponse)
        return Found(walletResponse)
    }

    private suspend fun log(presentation: Presentation.Submitted, walletResponse: WalletResponseTO) {
        val event = PresentationEvent.VerifierGotWalletResponse(presentation.id, clock.instant(), walletResponse)
        publishPresentationEvent(event)
    }
}
