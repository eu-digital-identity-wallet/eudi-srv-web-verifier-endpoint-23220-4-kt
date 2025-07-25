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
import arrow.core.getOrElse
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.proc.BadJOSEException
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.RequestObjectRetrieved
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.Submitted
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateResponseCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyEncryptedResponse
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.regex.Pattern

/**
 * Represent the Authorization Response placed by wallet
 */
data class AuthorisationResponseTO(
    val state: String?, // this is the request_id
    val error: String? = null,
    val errorDescription: String? = null,
    val idToken: String? = null,
    val vpToken: JsonObject? = null,
)

sealed interface AuthorisationResponse {
    data class DirectPost(val response: AuthorisationResponseTO) : AuthorisationResponse
    data class DirectPostJwt(val encryptedResponse: Jwt) : AuthorisationResponse
}

private fun AuthorisationResponse.DirectPost.isErrorResponse(): Boolean = null != response.error

sealed interface WalletResponseValidationError {
    data object PresentationNotFound : WalletResponseValidationError

    data class UnexpectedResponseMode(
        val requestId: RequestId,
        val expected: ResponseModeOption,
        val actual: ResponseModeOption,
    ) : WalletResponseValidationError

    data object PresentationNotInExpectedState : WalletResponseValidationError

    data object IncorrectState : WalletResponseValidationError
    data object MissingIdToken : WalletResponseValidationError
    data class InvalidVpToken(val message: String, val cause: Throwable? = null) : WalletResponseValidationError
    data object MissingVpToken : WalletResponseValidationError
    data object RequiredCredentialSetNotSatisfied : WalletResponseValidationError
    data object InvalidPresentationSubmission : WalletResponseValidationError
    data class InvalidEncryptedResponse(val error: BadJOSEException) : WalletResponseValidationError
}

private suspend fun AuthorisationResponseTO.toDomain(
    presentation: RequestObjectRetrieved,
    validateVerifiablePresentation: ValidateVerifiablePresentation,
    vpFormats: VpFormats,
): Either<WalletResponseValidationError, WalletResponse> = either {
    fun requiredIdToken(): Jwt = ensureNotNull(idToken) { WalletResponseValidationError.MissingIdToken }

    suspend fun requiredVerifiablePresentations(query: DCQL): VerifiablePresentations =
        verifiablePresentations(
            query,
            presentation.id,
            presentation.nonce,
            presentation.type.transactionDataOrNull,
            validateVerifiablePresentation,
            vpFormats,
            presentation.issuerChain,
        ).bind()

    val maybeError: WalletResponse.Error? = error?.let { WalletResponse.Error(it, errorDescription) }
    maybeError ?: when (val type = presentation.type) {
        is PresentationType.IdTokenRequest -> WalletResponse.IdToken(requiredIdToken())
        is PresentationType.VpTokenRequest -> WalletResponse.VpToken(
            requiredVerifiablePresentations(type.query),
        )

        is PresentationType.IdAndVpToken -> WalletResponse.IdAndVpToken(
            requiredIdToken(),
            requiredVerifiablePresentations(type.query),
        )
    }
}

private val jsonPathPattern = Pattern.compile("(^\\$$|^\\$\\[\\d+\\]$)")

private suspend fun AuthorisationResponseTO.verifiablePresentations(
    query: DCQL,
    transactionId: TransactionId,
    nonce: Nonce,
    transactionData: NonEmptyList<TransactionData>?,
    validateVerifiablePresentation: ValidateVerifiablePresentation,
    vpFormats: VpFormats,
    issuerChain: NonEmptyList<X509Certificate>?,
): Either<WalletResponseValidationError, VerifiablePresentations> =
    either {
        ensureNotNull(vpToken) { WalletResponseValidationError.MissingVpToken }

        suspend fun JsonObject.toVerifiablePresentations(): Map<QueryId, List<VerifiablePresentation>> {
            val vpToken = Either.catch {
                Json.decodeFromJsonElement<Map<QueryId, List<JsonElement>>>(this)
            }.getOrElse { raise(WalletResponseValidationError.InvalidVpToken("Failed to decode vp_token", it)) }

            val credentialQueries = query.credentials.associateBy { it.id }
            return vpToken.mapValues { (queryId, value) ->
                val format = credentialQueries[queryId]?.format
                    ?: raise(
                        WalletResponseValidationError.InvalidVpToken(
                            "vp_token references non-existing Credential Query",
                            null,
                        ),
                    )
                val unvalidatedVerifiablePresentations = value.map { it.toVerifiablePresentation(format).bind() }
                val applicableTransactionData = transactionData?.filter {
                    queryId.value in it.credentialIds
                }?.toNonEmptyListOrNull()
                val vpFormat = vpFormats.vpFormat(
                    format,
                    WalletResponseValidationError.InvalidVpToken(
                        "vp_token contains a Verifiable Presentation in an unsupported format",
                        null,
                    ),
                ).bind()
                unvalidatedVerifiablePresentations.map {
                    validateVerifiablePresentation(
                        transactionId,
                        it,
                        vpFormat,
                        nonce,
                        applicableTransactionData,
                        issuerChain,
                    ).bind()
                }
            }
        }

        val verifiablePresentations = vpToken.toVerifiablePresentations()
        ensure(query.satisfiedBy(verifiablePresentations)) {
            WalletResponseValidationError.RequiredCredentialSetNotSatisfied
        }

        VerifiablePresentations(verifiablePresentations)
    }

private fun JsonElement.toVerifiablePresentation(format: Format): Either<WalletResponseValidationError, VerifiablePresentation> =
    either {
        fun JsonElement.asString(): VerifiablePresentation.Str {
            val element = this@asString
            ensure(element is JsonPrimitive && element.isString) {
                WalletResponseValidationError.InvalidVpToken("vp_token contains a non-string element", null)
            }
            return VerifiablePresentation.Str(element.content, format)
        }

        fun JsonElement.asStringOrObject(): VerifiablePresentation =
            when (val element = this@asStringOrObject) {
                is JsonPrimitive -> {
                    ensure(
                        element.isString,
                    ) { WalletResponseValidationError.InvalidVpToken("vp_token contains a non-string element", null) }
                    VerifiablePresentation.Str(element.content, format)
                }

                is JsonObject -> VerifiablePresentation.Json(element, format)
                else -> raise(
                    WalletResponseValidationError.InvalidVpToken(
                        "vp_token must contain either json strings, or json objects",
                        null,
                    ),
                )
            }

        val element = this@toVerifiablePresentation
        when (format) {
            Format.MsoMdoc -> element.asString()
            Format.SdJwtVc -> element.asStringOrObject()
            else -> element.asStringOrObject()
        }
    }

private fun VpFormats.vpFormat(
    format: Format,
    ifInvalid: WalletResponseValidationError,
): Either<WalletResponseValidationError, VpFormat> =
    either {
        when (format.value) {
            SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT -> sdJwtVc
            OpenId4VPSpec.FORMAT_MSO_MDOC -> msoMdoc
            else -> raise(ifInvalid)
        }
    }

@Serializable
data class WalletResponseAcceptedTO(
    @SerialName("redirect_uri") val redirectUri: String,
)

/**
 * This is use-case 12 of the [Presentation] process.
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
    private val verifyEncryptedResponse: VerifyEncryptedResponse,
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
        when (val responseMode = presentation.responseMode) {
            ResponseMode.DirectPost -> {
                ensure(walletResponse is AuthorisationResponse.DirectPost) {
                    WalletResponseValidationError.UnexpectedResponseMode(
                        presentation.requestId,
                        expected = ResponseModeOption.DirectPost,
                        actual = ResponseModeOption.DirectPostJwt,
                    )
                }
                walletResponse.response
            }

            is ResponseMode.DirectPostJwt -> {
                when (walletResponse) {
                    is AuthorisationResponse.DirectPost -> {
                        ensure(walletResponse.isErrorResponse()) {
                            WalletResponseValidationError.UnexpectedResponseMode(
                                presentation.requestId,
                                expected = ResponseModeOption.DirectPostJwt,
                                actual = ResponseModeOption.DirectPost,
                            )
                        }
                        walletResponse.response
                    }

                    is AuthorisationResponse.DirectPostJwt ->
                        verifyEncryptedResponse(
                            ephemeralResponseEncryptionKey = responseMode.ephemeralResponseEncryptionKey,
                            encryptedResponse = walletResponse.encryptedResponse,
                            apv = presentation.nonce,
                        ).getOrElse {
                            when (it) {
                                is BadJOSEException -> raise(WalletResponseValidationError.InvalidEncryptedResponse(it))
                                else -> throw it
                            }
                        }
                }
            }
        }
    }

    private suspend fun submit(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO,
    ): Either<WalletResponseValidationError, Submitted> = either {
        // add the wallet response to the presentation
        val walletResponse = responseObject.toDomain(
            presentation,
            validateVerifiablePresentation,
            verifierConfig.clientMetaData.vpFormats,
        ).bind()

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
private fun AuthorisationResponse.responseModeOption(): ResponseModeOption = when (this) {
    is AuthorisationResponse.DirectPost -> ResponseModeOption.DirectPost
    is AuthorisationResponse.DirectPostJwt -> ResponseModeOption.DirectPostJwt
}

private fun DCQL.satisfiedBy(response: Map<QueryId, List<VerifiablePresentation>>): Boolean =
    credentialSets?.filter { credentialSet -> credentialSet.required ?: true }
        ?.map { credentialSet -> credentialSet.options.any { option -> response.keys.containsAll(option) } }
        ?.fold(true, Boolean::and)
        ?: response.keys.containsAll(credentials.map { it.id })
