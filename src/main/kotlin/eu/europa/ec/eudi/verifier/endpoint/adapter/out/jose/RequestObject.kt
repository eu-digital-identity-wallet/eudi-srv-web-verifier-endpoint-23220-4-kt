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

import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import java.net.URL
import java.time.Clock
import java.time.Instant

internal data class RequestObject(
    val clientId: String,
    val clientIdScheme: String,
    val responseType: List<String>,
    val presentationDefinitionUri: URL?,
    val presentationDefinition: PresentationDefinition? = null,
    val scope: List<String>,
    val idTokenType: List<String>,
    val nonce: String,
    val responseMode: String,
    val responseUri: URL?,
    val aud: List<String>,
    val state: String,
    val issuedAt: Instant,
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
            IdTokenType.AttesterSigned -> "attester_signed_id_token"
            IdTokenType.SubjectSigned -> "subject_signed_id_token"
        }
    }
    val maybePresentationDefinition = type.presentationDefinitionOrNull
    val presentationDefinitionUri = maybePresentationDefinition?.let {
        when (val option = verifierConfig.presentationDefinitionEmbedOption) {
            is EmbedOption.ByValue -> null
            is EmbedOption.ByReference -> option.buildUrl(presentation.requestId)
        }
    }
    val presentationDefinition = maybePresentationDefinition?.let { presentationDefinition ->
        when (verifierConfig.presentationDefinitionEmbedOption) {
            is EmbedOption.ByValue -> presentationDefinition
            is EmbedOption.ByReference -> null
        }
    }
    val responseType = when (type) {
        is PresentationType.IdTokenRequest -> listOf("id_token")
        is PresentationType.VpTokenRequest -> listOf("vp_token")
        is PresentationType.IdAndVpToken -> listOf("vp_token", "id_token")
    }

    val aud = when (type) {
        is PresentationType.IdTokenRequest -> emptyList()
        else -> listOf("https://self-issued.me/v2")
    }

    return RequestObject(
        clientId = verifierConfig.clientId,
        clientIdScheme = verifierConfig.clientIdScheme,
        scope = scope,
        idTokenType = idTokenType,
        presentationDefinitionUri = presentationDefinitionUri,
        presentationDefinition = presentationDefinition,
        responseType = responseType,
        aud = aud,
        nonce = presentation.nonce.value,
        state = presentation.requestId.value,
        responseMode = "direct_post", // or direct_post for direct submission
        responseUri = verifierConfig.responseUriBuilder(presentation.requestId),
        issuedAt = clock.instant(),
    )
}
