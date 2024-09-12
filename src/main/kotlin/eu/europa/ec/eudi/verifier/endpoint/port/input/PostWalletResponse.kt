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
import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.prex.PresentationSubmission
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
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.time.Clock

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
    data class DirectPostJwt(val state: String?, val jarm: Jwt) : AuthorisationResponse
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

    data object IncorrectStateInJarm : WalletResponseValidationError
    data object MissingIdToken : WalletResponseValidationError
    data object InvalidVpToken : WalletResponseValidationError
    data object MissingVpTokenOrPresentationSubmission : WalletResponseValidationError
}

context(Raise<WalletResponseValidationError>)
internal fun AuthorisationResponseTO.toDomain(presentation: RequestObjectRetrieved): WalletResponse {
    fun requiredIdToken(): WalletResponse.IdToken {
        ensureNotNull(idToken) { WalletResponseValidationError.MissingIdToken }
        return WalletResponse.IdToken(idToken)
    }

    fun requiredVpToken(): WalletResponse.VpToken {
        fun JsonElement.toVerifiablePresentations(): NonEmptyList<VerifiablePresentation> {
            fun JsonElement.toVerifiablePresentation(): VerifiablePresentation =
                when (this) {
                    is JsonPrimitive -> {
                        ensure(isString) { WalletResponseValidationError.InvalidVpToken }
                        VerifiablePresentation.Generic(content)
                    }
                    is JsonObject -> VerifiablePresentation.Json(this)
                    else -> raise(WalletResponseValidationError.InvalidVpToken)
                }
            return when (this) {
                is JsonPrimitive, is JsonObject -> nonEmptyListOf(toVerifiablePresentation())
                is JsonArray ->
                    map { it.toVerifiablePresentation() }
                        .toNonEmptyListOrNull()
                        ?: raise(WalletResponseValidationError.InvalidVpToken)
                else -> raise(WalletResponseValidationError.InvalidVpToken)
            }
        }

        ensureNotNull(vpToken) { WalletResponseValidationError.MissingVpTokenOrPresentationSubmission }
        ensureNotNull(presentationSubmission) { WalletResponseValidationError.MissingVpTokenOrPresentationSubmission }
        return WalletResponse.VpToken(vpToken.toVerifiablePresentations(), presentationSubmission)
    }

    fun requiredIdAndVpToken(): WalletResponse.IdAndVpToken {
        val a = requiredIdToken()
        val b = requiredVpToken()
        return WalletResponse.IdAndVpToken(a.idToken, b.vpToken, b.presentationSubmission)
    }

    val maybeError: WalletResponse.Error? = error?.let { WalletResponse.Error(it, errorDescription) }

    return maybeError ?: when (presentation.type) {
        is PresentationType.IdTokenRequest -> WalletResponse.IdToken(requiredIdToken().idToken)
        is PresentationType.VpTokenRequest -> WalletResponse.VpToken(
            requiredVpToken().vpToken,
            requiredVpToken().presentationSubmission,
        )

        is PresentationType.IdAndVpToken -> WalletResponse.IdAndVpToken(
            requiredIdAndVpToken().idToken,
            requiredIdAndVpToken().vpToken,
            requiredIdAndVpToken().presentationSubmission,
        )
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

    context(Raise<WalletResponseValidationError>)
    suspend operator fun invoke(walletResponse: AuthorisationResponse): WalletResponseAcceptedTO?
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
) : PostWalletResponse {

    context(Raise<WalletResponseValidationError>)
    override suspend operator fun invoke(
        walletResponse: AuthorisationResponse,
    ): WalletResponseAcceptedTO? = coroutineScope {
        val presentation = loadPresentation(walletResponse)

        doInvoke(presentation, walletResponse).fold(
            ifLeft = { cause ->
                logFailure(presentation, cause)
                raise(cause)
            },
            ifRight = { (submitted, accepted) ->
                logWalletResponsePosted(submitted, accepted)
                accepted
            },
        )
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

            val responseObject = responseObject(walletResponse, presentation)
            val submitted = submit(presentation, responseObject).also { storePresentation(it) }

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

    context(Raise<WalletResponseValidationError>)
    private suspend fun loadPresentation(walletResponse: AuthorisationResponse): Presentation {
        val state = when (walletResponse) {
            is AuthorisationResponse.DirectPost -> walletResponse.response.state
            is AuthorisationResponse.DirectPostJwt -> walletResponse.state
        }
        ensureNotNull(state) { WalletResponseValidationError.MissingState }
        val requestId = RequestId(state)

        val presentation = loadPresentationByRequestId(requestId)
        return ensureNotNull(presentation) { WalletResponseValidationError.PresentationNotFound }
    }

    context(Raise<WalletResponseValidationError>)
    private fun responseObject(
        walletResponse: AuthorisationResponse,
        presentation: RequestObjectRetrieved,
    ): AuthorisationResponseTO = when (walletResponse) {
        is AuthorisationResponse.DirectPost -> walletResponse.response
        is AuthorisationResponse.DirectPostJwt -> {
            val response = verifyJarmJwtSignature(
                jarmOption = verifierConfig.clientMetaData.jarmOption,
                ephemeralEcPrivateKey = presentation.ephemeralEcPrivateKey,
                jarmJwt = walletResponse.jarm,
            ).getOrThrow()
            ensure(response.state == walletResponse.state) { WalletResponseValidationError.IncorrectStateInJarm }
            response
        }
    }

    context(Raise<WalletResponseValidationError>)
    private suspend fun submit(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO,
    ): Submitted {
        // add the wallet response to the presentation
        val walletResponse = responseObject.toDomain(presentation)
        val responseCode = when (presentation.getWalletResponseMethod) {
            GetWalletResponseMethod.Poll -> null
            is GetWalletResponseMethod.Redirect -> generateResponseCode()
        }
        return presentation.submit(clock, walletResponse, responseCode).getOrThrow()
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
