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
package eu.europa.ec.eudi.verifier.endpoint.domain

import arrow.core.NonEmptyList
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationSubmission
import kotlinx.serialization.json.JsonObject
import java.time.Clock
import java.time.Instant

@JvmInline
value class TransactionId(val value: String) {
    init {
        require(value.isNotBlank())
    }
}

/**
 * This is an identifier of the [Presentation]
 * which is communicated to the wallet as <em>state</em>.
 * As such, it is being used to correlate an authorization response
 * send from wallet with a [Presentation]
 */
@JvmInline
value class RequestId(val value: String) {
    init {
        require(value.isNotBlank())
    }
}

@JvmInline
value class Nonce(val value: String) {
    init {
        require(value.isNotBlank())
    }
}

typealias Jwt = String

enum class IdTokenType {
    SubjectSigned,
    AttesterSigned,
}

/**
 * Represents what the [Presentation] is asking
 * from the wallet
 */
sealed interface PresentationType {
    data class IdTokenRequest(
        val idTokenType: List<IdTokenType>,
    ) : PresentationType

    data class VpTokenRequest(
        val presentationDefinition: PresentationDefinition,
    ) : PresentationType

    data class IdAndVpToken(
        val idTokenType: List<IdTokenType>,
        val presentationDefinition: PresentationDefinition,
    ) : PresentationType
}

val PresentationType.presentationDefinitionOrNull: PresentationDefinition?
    get() = when (this) {
        is PresentationType.IdTokenRequest -> null
        is PresentationType.VpTokenRequest -> presentationDefinition
        is PresentationType.IdAndVpToken -> presentationDefinition
    }

sealed interface VerifiablePresentation {

    @JvmInline
    value class Generic(val value: String) : VerifiablePresentation {
        init {
            require(value.isNotBlank()) { "VpToken cannot be blank" }
        }
    }

    @JvmInline
    value class Json(val value: JsonObject) : VerifiablePresentation {
        init {
            require(value.isNotEmpty()) { "VpToken must contain claims" }
        }
    }
}

sealed interface WalletResponse {

    data class IdToken(
        val idToken: Jwt,
    ) : WalletResponse {
        init {
            require(idToken.isNotEmpty())
        }
    }

    data class VpToken(
        val vpToken: NonEmptyList<VerifiablePresentation>,
        val presentationSubmission: PresentationSubmission,
    ) : WalletResponse

    data class IdAndVpToken(
        val idToken: Jwt,
        val vpToken: NonEmptyList<VerifiablePresentation>,
        val presentationSubmission: PresentationSubmission,
    ) : WalletResponse {
        init {
            require(idToken.isNotEmpty())
        }
    }

    data class Error(val value: String, val description: String?) : WalletResponse
}

@JvmInline
value class EphemeralEncryptionKeyPairJWK(val value: String) {
    companion object
}

@JvmInline
value class ResponseCode(val value: String)

sealed interface GetWalletResponseMethod {
    data object Poll : GetWalletResponseMethod
    data class Redirect(val redirectUriTemplate: String) : GetWalletResponseMethod
}

/**
 * The entity that represents the presentation process
 */
sealed interface Presentation {
    val id: TransactionId
    val initiatedAt: Instant
    val type: PresentationType

    /**
     * A presentation process that has been just requested
     */
    class Requested(
        override val id: TransactionId,
        override val initiatedAt: Instant,
        override val type: PresentationType,
        val requestId: RequestId,
        val nonce: Nonce,
        val ephemeralEcPrivateKey: EphemeralEncryptionKeyPairJWK?,
        val responseMode: ResponseModeOption,
        val presentationDefinitionMode: EmbedOption<RequestId>,
        val getWalletResponseMethod: GetWalletResponseMethod,
    ) : Presentation

    /**
     * A presentation process for which the wallet has obtained the request object.
     * Depending on the configuration of the verifier, this can be done
     * as part of the initialization of the process (when using request JAR parameter)
     * or later on (when using request_uri JAR parameter)
     */
    class RequestObjectRetrieved private constructor(
        override val id: TransactionId,
        override val initiatedAt: Instant,
        override val type: PresentationType,
        val requestId: RequestId,
        val requestObjectRetrievedAt: Instant,
        val nonce: Nonce,
        val ephemeralEcPrivateKey: EphemeralEncryptionKeyPairJWK?,
        val responseMode: ResponseModeOption,
        val getWalletResponseMethod: GetWalletResponseMethod,
    ) : Presentation {
        init {
            require(initiatedAt.isBefore(requestObjectRetrievedAt) || initiatedAt == requestObjectRetrievedAt)
        }

        companion object {
            fun requestObjectRetrieved(requested: Requested, at: Instant): Result<RequestObjectRetrieved> =
                runCatching {
                    RequestObjectRetrieved(
                        requested.id,
                        requested.initiatedAt,
                        requested.type,
                        requested.requestId,
                        at,
                        requested.nonce,
                        requested.ephemeralEcPrivateKey,
                        requested.responseMode,
                        requested.getWalletResponseMethod,
                    )
                }
        }
    }

    /**
     * A presentation process that has been just submitted by the wallet to the verifier backend
     */
    class Submitted private constructor(
        override val id: TransactionId,
        override val initiatedAt: Instant,
        override val type: PresentationType,
        val requestId: RequestId,
        var requestObjectRetrievedAt: Instant,
        var submittedAt: Instant,
        val walletResponse: WalletResponse,
        val nonce: Nonce,
        val responseCode: ResponseCode?,
    ) : Presentation {

        init {
            require(initiatedAt.isBefore(Instant.now()))
        }

        companion object {
            fun submitted(
                requestObjectRetrieved: RequestObjectRetrieved,
                at: Instant,
                walletResponse: WalletResponse,
                responseCode: ResponseCode?,
            ): Result<Submitted> = runCatching {
                with(requestObjectRetrieved) {
                    Submitted(
                        id,
                        initiatedAt,
                        type,
                        requestId,
                        requestObjectRetrievedAt,
                        at,
                        walletResponse,
                        nonce,
                        responseCode,
                    )
                }
            }
        }
    }

    class TimedOut private constructor(
        override val id: TransactionId,
        override val initiatedAt: Instant,
        override val type: PresentationType,
        val requestObjectRetrievedAt: Instant? = null,
        val submittedAt: Instant? = null,
        val timedOutAt: Instant,
    ) : Presentation {
        companion object {
            fun timeOut(presentation: Requested, at: Instant): Result<TimedOut> = runCatching {
                require(presentation.initiatedAt.isBefore(at))
                TimedOut(presentation.id, presentation.initiatedAt, presentation.type, null, null, at)
            }

            fun timeOut(presentation: RequestObjectRetrieved, at: Instant): Result<TimedOut> = runCatching {
                require(presentation.initiatedAt.isBefore(at))
                TimedOut(
                    presentation.id,
                    presentation.initiatedAt,
                    presentation.type,
                    presentation.requestObjectRetrievedAt,
                    null,
                    at,
                )
            }

            fun timeOut(presentation: Submitted, at: Instant): Result<TimedOut> = runCatching {
                require(presentation.initiatedAt.isBefore(at))
                TimedOut(
                    presentation.id,
                    presentation.initiatedAt,
                    presentation.type,
                    presentation.requestObjectRetrievedAt,
                    presentation.submittedAt,
                    at,
                )
            }
        }
    }
}

fun Presentation.isExpired(at: Instant): Boolean {
    fun Instant.isBeforeOrEqual(at: Instant) = isBefore(at) || this == at
    return when (this) {
        is Presentation.Requested -> initiatedAt.isBeforeOrEqual(at)
        is Presentation.RequestObjectRetrieved -> requestObjectRetrievedAt.isBeforeOrEqual(at)
        is Presentation.TimedOut -> false
        is Presentation.Submitted -> initiatedAt.isBeforeOrEqual(at)
    }
}

fun Presentation.Requested.retrieveRequestObject(clock: Clock): Result<Presentation.RequestObjectRetrieved> =
    Presentation.RequestObjectRetrieved.requestObjectRetrieved(this, clock.instant())

fun Presentation.Requested.timedOut(clock: Clock): Result<Presentation.TimedOut> =
    Presentation.TimedOut.timeOut(this, clock.instant())

fun Presentation.RequestObjectRetrieved.timedOut(clock: Clock): Result<Presentation.TimedOut> =
    Presentation.TimedOut.timeOut(this, clock.instant())

fun Presentation.RequestObjectRetrieved.submit(
    clock: Clock,
    walletResponse: WalletResponse,
    responseCode: ResponseCode?,
): Result<Presentation.Submitted> =
    Presentation.Submitted.submitted(this, clock.instant(), walletResponse, responseCode)

fun Presentation.Submitted.timedOut(clock: Clock): Result<Presentation.TimedOut> =
    Presentation.TimedOut.timeOut(this, clock.instant())
