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

import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GeneratePresentationId
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.SignRequestObject
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.time.Clock

/**
 * Represent the kind of [Presentation] process
 * a caller wants to initiate
 * It could be either a request (to the wallet) to present
 * a id_token, a vp_token or both
 */
@Serializable
enum class PresentationTypeTO {
    @SerialName("id_token")
    IdTokenRequest,

    @SerialName("vp_token")
    VpTokenRequest,

    @SerialName("vp_token id_token")
    IdAndVpTokenRequest,
}

/**
 * Specifies what kind of id_token to request
 */
@Serializable
enum class IdTokenTypeTO {
    @SerialName("subject_signed_id_token")
    SubjectSigned,

    @SerialName("attester_signed_id_token")
    AttesterSigned,
}

@Serializable
data class InitTransactionTO(
    @SerialName("type") val type: PresentationTypeTO = PresentationTypeTO.IdAndVpTokenRequest,
    @SerialName("id_token_type") val idTokenType: IdTokenTypeTO? = null,
    @SerialName("presentation_definition") val presentationDefinition: PresentationDefinition? = null,
    @SerialName("nonce") val nonce: String? = null,
)

/**
 * Possible validation errors of caller's input
 */
enum class ValidationError {
    MissingPresentationDefinition,
    MissingNonce,
}

/**
 * Carrier of [ValidationError]
 */
data class ValidationException(val error: ValidationError) : RuntimeException()

/**
 * The return value of successfully [initializing][InitTransaction] a [Presentation]
 *
 */
@Serializable
data class JwtSecuredAuthorizationRequestTO(
    @Required @SerialName("presentation_id") val presentationId: String,
    @Required @SerialName("client_id") val clientId: String,
    @SerialName("request") val request: String? = null,
    @SerialName("request_uri") val requestUri: String?,
)

/**
 * This is a use case that initializes the [Presentation] process.
 *
 * The caller may define via [InitTransactionTO] what kind of transaction wants to initiate
 * This is represented by [PresentationTypeTO].
 *
 * Use case will initialize a [Presentation] process
 */
interface InitTransaction {
    suspend operator fun invoke(initTransactionTO: InitTransactionTO): Result<JwtSecuredAuthorizationRequestTO>
}

/**
 * The default implementation of the use case
 */
class InitTransactionLive(
    private val generatePresentationId: GeneratePresentationId,
    private val generateRequestId: GenerateRequestId,
    private val storePresentation: StorePresentation,
    private val signRequestObject: SignRequestObject,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock,

) : InitTransaction {
    override suspend fun invoke(initTransactionTO: InitTransactionTO): Result<JwtSecuredAuthorizationRequestTO> =
        runCatching {
            // validate input
            val (nonce, type) = initTransactionTO.toDomain().getOrThrow()

            // Initialize presentation
            val requestedPresentation = Presentation.Requested(
                id = generatePresentationId(),
                initiatedAt = clock.instant(),
                requestId = generateRequestId(),
                type = type,
                nonce = nonce,
            )
            // create request, which may update presentation
            val (updatedPresentation, request) = createRequest(requestedPresentation)

            storePresentation(updatedPresentation)
            request
        }

    /**
     * Creates a request and depending on the case updates also the [requestedPresentation]
     *
     * If the verifier has been configured to use request parameter then
     * presentation will be updated to [Presentation.RequestObjectRetrieved].
     *
     * Otherwise, [requestedPresentation] will remain as is
     */
    private fun createRequest(requestedPresentation: Presentation.Requested): Pair<Presentation, JwtSecuredAuthorizationRequestTO> =
        when (val requestJarOption = verifierConfig.requestJarOption) {
            is EmbedOption.ByValue -> {
                val jwt = signRequestObject(verifierConfig, clock, requestedPresentation).getOrThrow()
                val requestObjectRetrieved = requestedPresentation.retrieveRequestObject(clock).getOrThrow()
                requestObjectRetrieved to JwtSecuredAuthorizationRequestTO(
                    requestedPresentation.id.value,
                    verifierConfig.clientId,
                    jwt,
                    null,
                )
            }

            is EmbedOption.ByReference -> {
                val requestUri = requestJarOption.buildUrl(requestedPresentation.requestId).toExternalForm()
                requestedPresentation to JwtSecuredAuthorizationRequestTO(
                    requestedPresentation.id.value,
                    verifierConfig.clientId,
                    null,
                    requestUri,
                )
            }
        }
}

internal fun InitTransactionTO.toDomain(): Result<Pair<Nonce, PresentationType>> {
    fun requiredIdTokenType() =
        Result.success(idTokenType?.toDomain()?.let { listOf(it) } ?: emptyList())

    fun requiredPresentationDefinition() =
        if (presentationDefinition != null) {
            Result.success(presentationDefinition)
        } else Result.failure(ValidationException(ValidationError.MissingPresentationDefinition))

    fun requiredNonce() =
        if (!nonce.isNullOrBlank()) {
            Result.success(Nonce(nonce))
        } else Result.failure(ValidationException(ValidationError.MissingNonce))

    return runCatching {
        val presentationType = when (type) {
            PresentationTypeTO.IdTokenRequest ->
                PresentationType.IdTokenRequest(requiredIdTokenType().getOrThrow())

            PresentationTypeTO.VpTokenRequest ->
                PresentationType.VpTokenRequest(requiredPresentationDefinition().getOrThrow())

            PresentationTypeTO.IdAndVpTokenRequest -> {
                val idTokenTypes = requiredIdTokenType().getOrThrow()
                val pd = requiredPresentationDefinition().getOrThrow()
                PresentationType.IdAndVpToken(idTokenTypes, pd)
            }
        }

        val nonce = requiredNonce().getOrThrow()

        nonce to presentationType
    }
}

private fun IdTokenTypeTO.toDomain(): IdTokenType = when (this) {
    IdTokenTypeTO.SubjectSigned -> IdTokenType.SubjectSigned
    IdTokenTypeTO.AttesterSigned -> IdTokenType.AttesterSigned
}
