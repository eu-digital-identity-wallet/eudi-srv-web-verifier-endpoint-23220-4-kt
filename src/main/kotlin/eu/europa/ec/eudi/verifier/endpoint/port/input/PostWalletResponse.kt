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

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationSubmission
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.JsonPathReader
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.RequestObjectRetrieved
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.Submitted
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateResponseCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyJarmJwtSignature
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.time.Clock
import java.util.regex.Pattern

/**
 * Represent the Authorisation Response placed by wallet
 */
data class AuthorisationResponseTO(
    val state: String?, // this is the request_id
    val error: String? = null,
    val errorDescription: String? = null,
    val idToken: String? = null,
    val vpToken: JsonElement? = null,
    val presentationSubmission: PresentationSubmission? = null,
)

sealed interface AuthorisationResponse {
    data class DirectPost(val response: AuthorisationResponseTO) : AuthorisationResponse
    data class DirectPostJwt(val jarm: Jwt) : AuthorisationResponse
}

sealed interface WalletResponseValidationError {
    data object MissingState : WalletResponseValidationError
    data object PresentationNotFound : WalletResponseValidationError

    data class UnexpectedResponseMode(
        val requestId: RequestId,
        val expected: ResponseModeOption,
        val actual: ResponseModeOption,
    ) : WalletResponseValidationError

    data object PresentationNotInExpectedState : WalletResponseValidationError

    data object IncorrectState : WalletResponseValidationError
    data object MissingIdToken : WalletResponseValidationError
    data object InvalidVpToken : WalletResponseValidationError
    data object MissingVpToken : WalletResponseValidationError
    data object MissingPresentationSubmission : WalletResponseValidationError
    data object PresentationSubmissionMustNotBePresent : WalletResponseValidationError
    data object RequiredCredentialSetNotSatisfied : WalletResponseValidationError
    data object InvalidPresentationSubmission : WalletResponseValidationError
}

private suspend fun AuthorisationResponseTO.toDomain(
    presentation: RequestObjectRetrieved,
    validateVerifiablePresentation: ValidateVerifiablePresentation,
): Either<WalletResponseValidationError, WalletResponse> = either {
    fun requiredIdToken(): Jwt = ensureNotNull(idToken) { WalletResponseValidationError.MissingIdToken }

    suspend fun requiredVpContent(presentationQuery: PresentationQuery): VpContent =
        when (presentationQuery) {
            is PresentationQuery.ByPresentationDefinition ->
                presentationExchangeVpContent(
                    presentationQuery.presentationDefinition,
                    presentation.nonce,
                    validateVerifiablePresentation,
                )
            is PresentationQuery.ByDigitalCredentialsQueryLanguage ->
                dcqlVpContent(
                    presentationQuery.query,
                    presentation.nonce,
                    validateVerifiablePresentation,
                )
        }.bind()

    val maybeError: WalletResponse.Error? = error?.let { WalletResponse.Error(it, errorDescription) }
    maybeError ?: when (val type = presentation.type) {
        is PresentationType.IdTokenRequest -> WalletResponse.IdToken(requiredIdToken())
        is PresentationType.VpTokenRequest -> WalletResponse.VpToken(
            requiredVpContent(type.presentationQuery),
        )

        is PresentationType.IdAndVpToken -> WalletResponse.IdAndVpToken(
            requiredIdToken(),
            requiredVpContent(type.presentationQuery),
        )
    }
}

private val jsonPathPattern = Pattern.compile("(^\\$$|^\\$\\[\\d+\\]$)")

private suspend fun AuthorisationResponseTO.presentationExchangeVpContent(
    presentationDefinition: PresentationDefinition,
    nonce: Nonce,
    validateVerifiablePresentation: ValidateVerifiablePresentation,
): Either<WalletResponseValidationError, VpContent.PresentationExchange> =
    either {
        ensureNotNull(vpToken) { WalletResponseValidationError.MissingVpToken }
        ensureNotNull(presentationSubmission) { WalletResponseValidationError.MissingPresentationSubmission }
        ensure(presentationSubmission.definitionId == presentationDefinition.id) {
            WalletResponseValidationError.InvalidPresentationSubmission
        }

        val descriptorMaps = presentationSubmission.descriptorMaps
            .toNonEmptyListOrNull()
            ?: raise(WalletResponseValidationError.InvalidPresentationSubmission)
        val vpTokenReader = JsonPathReader(vpToken)
        val verifiablePresentations = descriptorMaps.map {
            ensure(jsonPathPattern.matcher(it.path.value).matches()) { WalletResponseValidationError.InvalidPresentationSubmission }

            val element = vpTokenReader.readPath(it.path.value).getOrNull() ?: raise(WalletResponseValidationError.InvalidVpToken)
            val format = Format(it.format)
            val unvalidatedVerifiablePresentation = element.toVerifiablePresentation(format).bind()
            validateVerifiablePresentation(unvalidatedVerifiablePresentation, nonce)
                .getOrElse { raise(WalletResponseValidationError.InvalidVpToken) }
        }.distinct()

        VpContent.PresentationExchange(verifiablePresentations, presentationSubmission)
    }

private suspend fun AuthorisationResponseTO.dcqlVpContent(
    query: DCQL,
    nonce: Nonce,
    validateVerifiablePresentation: ValidateVerifiablePresentation,
): Either<WalletResponseValidationError, VpContent.DCQL> =
    either {
        ensureNotNull(vpToken) { WalletResponseValidationError.MissingVpToken }
        ensure(presentationSubmission == null) { WalletResponseValidationError.PresentationSubmissionMustNotBePresent }

        suspend fun JsonElement.toVerifiablePresentations(): Map<QueryId, VerifiablePresentation> {
            val vpToken = runCatching {
                Json.decodeFromJsonElement<Map<QueryId, JsonElement>>(this)
            }.getOrElse { raise(WalletResponseValidationError.InvalidVpToken) }

            val credentialQueries = query.credentials.associateBy { it.id }
            return vpToken.mapValues { (queryId, value) ->
                val format = credentialQueries[queryId]?.format ?: raise(WalletResponseValidationError.InvalidVpToken)
                val unvalidatedVerifiablePresentation = value.toVerifiablePresentation(format).bind()
                validateVerifiablePresentation(unvalidatedVerifiablePresentation, nonce)
                    .getOrElse { raise(WalletResponseValidationError.InvalidVpToken) }
            }
        }

        val verifiablePresentations = vpToken.toVerifiablePresentations()
        ensure(query.satisfiedBy(verifiablePresentations)) {
            WalletResponseValidationError.RequiredCredentialSetNotSatisfied
        }

        VpContent.DCQL(verifiablePresentations)
    }

private fun JsonElement.toVerifiablePresentation(format: Format): Either<WalletResponseValidationError, VerifiablePresentation> =
    either {
        fun JsonElement.asString(): VerifiablePresentation.Str {
            val element = this@asString
            ensure(element is JsonPrimitive && element.isString) { WalletResponseValidationError.InvalidVpToken }
            return VerifiablePresentation.Str(element.content, format)
        }

        fun JsonElement.asStringOrObject(): VerifiablePresentation =
            when (val element = this@asStringOrObject) {
                is JsonPrimitive -> {
                    ensure(element.isString) { WalletResponseValidationError.InvalidVpToken }
                    VerifiablePresentation.Str(element.content, format)
                }
                is JsonObject -> VerifiablePresentation.Json(element, format)
                else -> raise(WalletResponseValidationError.InvalidVpToken)
            }

        val element = this@toVerifiablePresentation
        when (format) {
            Format.MsoMdoc -> element.asString()
            Format(SdJwtVcSpec.MEDIA_SUBTYPE_VC_SD_JWT), Format.SdJwtVc -> element.asStringOrObject()
            else -> element.asStringOrObject()
        }
    }

@Serializable
data class WalletResponseAcceptedTO(
    @SerialName("redirect_uri") val redirectUri: String,
)

/**
 * This is use case 12 of the [Presentation] process.
 *
 * The caller (wallet) may POST the [AuthorisationResponseTO] to the verifier back-end
 */
fun interface PostWalletResponse {

    suspend operator fun invoke(
        requestId: RequestId,
        walletResponse: AuthorisationResponse,
    ): Either<WalletResponseValidationError, WalletResponseAcceptedTO?>
}

class PostWalletResponseLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val verifyJarmJwtSignature: VerifyJarmJwtSignature,
    private val clock: Clock,
    private val verifierConfig: VerifierConfig,
    private val generateResponseCode: GenerateResponseCode,
    private val createQueryWalletResponseRedirectUri: CreateQueryWalletResponseRedirectUri,
    private val publishPresentationEvent: PublishPresentationEvent,
    private val validateVerifiablePresentation: ValidateVerifiablePresentation,
) : PostWalletResponse {

    override suspend operator fun invoke(
        requestId: RequestId,
        walletResponse: AuthorisationResponse,
    ): Either<WalletResponseValidationError, WalletResponseAcceptedTO?> = either {
        val presentation = loadPresentation(requestId).bind()
        doInvoke(presentation, walletResponse)
            .onLeft { cause -> logFailure(presentation, cause) }
            .onRight { (submitted, accepted) -> logWalletResponsePosted(submitted, accepted) }
            .map { (_, accepted) -> accepted }
            .bind()
    }

    private suspend fun doInvoke(
        presentation: Presentation,
        walletResponse: AuthorisationResponse,
    ): Either<WalletResponseValidationError, Pair<Submitted, WalletResponseAcceptedTO?>> =
        either {
            ensure(presentation is RequestObjectRetrieved) {
                WalletResponseValidationError.PresentationNotInExpectedState
            }

            // Verify the AuthorisationResponse matches what is expected for the Presentation
            val responseMode = walletResponse.responseMode()
            ensure(presentation.responseMode == responseMode) {
                WalletResponseValidationError.UnexpectedResponseMode(
                    presentation.requestId,
                    expected = presentation.responseMode,
                    actual = responseMode,
                )
            }

            val responseObject = responseObject(walletResponse, presentation).bind()

            // Verify response `state` is RequestId
            ensure(presentation.requestId.value == responseObject.state) { WalletResponseValidationError.IncorrectState }

            // Submit the response
            val submitted = submit(presentation, responseObject)
                .bind()
                .also { storePresentation(it) }

            val accepted = when (val getWalletResponseMethod = presentation.getWalletResponseMethod) {
                is GetWalletResponseMethod.Redirect ->
                    with(createQueryWalletResponseRedirectUri) {
                        requireNotNull(submitted.responseCode) { "ResponseCode expected in Submitted state but not found" }
                        val redirectUri = getWalletResponseMethod.redirectUri(submitted.responseCode)
                        WalletResponseAcceptedTO(redirectUri.toExternalForm())
                    }

                GetWalletResponseMethod.Poll -> null
            }
            submitted to accepted
        }

    private suspend fun loadPresentation(requestId: RequestId): Either<WalletResponseValidationError, Presentation> =
        either {
            val presentation = loadPresentationByRequestId(requestId)
            ensureNotNull(presentation) { WalletResponseValidationError.PresentationNotFound }
        }

    private fun responseObject(
        walletResponse: AuthorisationResponse,
        presentation: RequestObjectRetrieved,
    ): Either<WalletResponseValidationError, AuthorisationResponseTO> = either {
        when (walletResponse) {
            is AuthorisationResponse.DirectPost -> walletResponse.response
            is AuthorisationResponse.DirectPostJwt -> {
                val response = verifyJarmJwtSignature(
                    jarmOption = verifierConfig.clientMetaData.jarmOption,
                    ephemeralEcPrivateKey = presentation.ephemeralEcPrivateKey,
                    jarmJwt = walletResponse.jarm,
                    apv = presentation.nonce,
                ).getOrThrow()
                response
            }
        }
    }

    private suspend fun submit(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO,
    ): Either<WalletResponseValidationError, Submitted> = either {
        // add the wallet response to the presentation
        val walletResponse = responseObject.toDomain(presentation, validateVerifiablePresentation).bind()
        val responseCode = when (presentation.getWalletResponseMethod) {
            GetWalletResponseMethod.Poll -> null
            is GetWalletResponseMethod.Redirect -> generateResponseCode()
        }
        presentation.submit(clock, walletResponse, responseCode).getOrThrow()
    }

    private suspend fun logWalletResponsePosted(p: Submitted, accepted: WalletResponseAcceptedTO?) {
        val event =
            PresentationEvent.WalletResponsePosted(p.id, p.submittedAt, p.walletResponse.toTO(), accepted)
        publishPresentationEvent(event)
    }

    private suspend fun logFailure(p: Presentation, cause: WalletResponseValidationError) {
        val event = PresentationEvent.WalletFailedToPostResponse(p.id, clock.instant(), cause)
        publishPresentationEvent(event)
    }
}

/**
 * Gets the [ResponseModeOption] that corresponds to the receiver [AuthorisationResponse].
 */
private fun AuthorisationResponse.responseMode(): ResponseModeOption = when (this) {
    is AuthorisationResponse.DirectPost -> ResponseModeOption.DirectPost
    is AuthorisationResponse.DirectPostJwt -> ResponseModeOption.DirectPostJwt
}

private fun DCQL.satisfiedBy(response: Map<QueryId, VerifiablePresentation>): Boolean =
    credentialSets?.filter { credentialSet -> credentialSet.required ?: true }
        ?.map { credentialSet -> credentialSet.options.any { option -> response.keys.containsAll(option) } }
        ?.fold(true, Boolean::and)
        ?: response.keys.containsAll(credentials.map { it.id })
