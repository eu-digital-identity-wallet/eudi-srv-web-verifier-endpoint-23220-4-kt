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
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationId
import eu.europa.ec.eudi.verifier.endpoint.domain.WalletResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.QueryResponse.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/**
 * Represent the [WalletResponse] as returned by the wallet
 */
@Serializable
@SerialName("wallet_response")
data class WalletResponseTO(
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("vp_token") val vpToken: JsonObject? = null,
    @SerialName("presentation_submission") val presentationSubmission: PresentationSubmission? = null,
    @SerialName("error") val error: String? = null,
    @SerialName("error_description") val errorDescription: String? = null,
)

private fun WalletResponse.toTO(): WalletResponseTO {
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
 * Given a [PresentationId] and a [Nonce] returns the [WalletResponse]
 */
interface GetWalletResponse {
    suspend operator fun invoke(presentationId: PresentationId, nonce: Nonce): QueryResponse<WalletResponseTO>
}

class GetWalletResponseLive(
    private val loadPresentationById: LoadPresentationById,
) : GetWalletResponse {
    override suspend fun invoke(presentationId: PresentationId, nonce: Nonce): QueryResponse<WalletResponseTO> {
        return when (val presentation = loadPresentationById(presentationId)) {
            null -> NotFound
            is Presentation.Submitted ->
                if (nonce == presentation.nonce) {
                    Found(presentation.walletResponse.toTO())
                } else {
                    InvalidState
                }
            else -> InvalidState
        }
    }
}
