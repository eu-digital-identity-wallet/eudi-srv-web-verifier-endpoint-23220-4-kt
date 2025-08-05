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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose

import eu.europa.ec.eudi.verifier.endpoint.domain.*
import java.net.URL
import java.time.Clock
import java.time.Instant

internal data class RequestObject(
    val verifierId: VerifierId,
    val responseType: List<String>,
    val dcqlQuery: DCQL? = null,
    val scope: List<String>,
    val idTokenType: List<String>,
    val nonce: String,
    val responseMode: String,
    val responseUri: URL?,
    val aud: List<String>,
    val state: String,
    val issuedAt: Instant,
    val transactionData: List<String>? = null,
)

internal fun requestObjectFromDomain(
    verifierConfig: VerifierConfig,
    clock: Clock,
    presentation: Presentation.Requested,
): RequestObject {
    val type = presentation.type
    val scope = when (type) {
        is PresentationType.IdTokenRequest -> listOf("openid")
        is PresentationType.VpTokenRequest -> emptyList()
        is PresentationType.IdAndVpToken -> listOf("openid")
    }
    val idTokenType = when (type) {
        is PresentationType.IdTokenRequest -> type.idTokenType
        is PresentationType.VpTokenRequest -> emptyList()
        is PresentationType.IdAndVpToken -> type.idTokenType
    }.map {
        when (it) {
            IdTokenType.AttesterSigned -> SIOP.ID_TOKEN_TYPE_ATTESTER_SIGNED_ID_TOKEN
            IdTokenType.SubjectSigned -> SIOP.ID_TOKEN_TYPE_SUBJECT_SIGNED_ID_TOKEN
        }
    }

    val responseType = when (type) {
        is PresentationType.IdTokenRequest -> listOf(RFC6749.ID_TOKEN)
        is PresentationType.VpTokenRequest -> listOf(OpenId4VPSpec.VP_TOKEN)
        is PresentationType.IdAndVpToken -> listOf(OpenId4VPSpec.VP_TOKEN, RFC6749.ID_TOKEN)
    }

    val aud = when (type) {
        is PresentationType.IdTokenRequest -> emptyList()
        else -> listOf("https://self-issued.me/v2")
    }

    val transactionData = type.transactionDataOrNull?.map { it.base64Url }

    return RequestObject(
        verifierId = verifierConfig.verifierId,
        scope = scope,
        idTokenType = idTokenType,
        dcqlQuery = type.queryOrNull,
        responseType = responseType,
        aud = aud,
        nonce = presentation.nonce.value,
        state = presentation.requestId.value,
        responseMode = when (presentation.responseMode) {
            ResponseMode.DirectPost -> OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST
            is ResponseMode.DirectPostJwt -> OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST_JWT
        },
        responseUri = verifierConfig.responseUriBuilder(presentation.requestId),
        issuedAt = clock.instant(),
        transactionData = transactionData,
    )
}
