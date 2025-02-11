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
 * The requirements of the Verifiable Presentations to be presented.
 */
sealed interface PresentationQuery {

    /**
     * The requirements of the Verifiable Presentations to be presented, expressed using Presentation Definition.
     */
    data class ByPresentationDefinition(val presentationDefinition: PresentationDefinition) : PresentationQuery

    /**
     * The requirements of the Verifiable Presentations to be presented, expressed using DCQL.
     */
    data class ByDigitalCredentialsQueryLanguage(val query: DCQL) : PresentationQuery
}

val PresentationQuery.presentationDefinitionOrNull: PresentationDefinition?
    get() = when (this) {
        is PresentationQuery.ByPresentationDefinition -> presentationDefinition
        is PresentationQuery.ByDigitalCredentialsQueryLanguage -> null
    }

val PresentationQuery.dcqlQueryOrNull: DCQL?
    get() = when (this) {
        is PresentationQuery.ByPresentationDefinition -> null
        is PresentationQuery.ByDigitalCredentialsQueryLanguage -> query
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
        val presentationQuery: PresentationQuery,
    ) : PresentationType

    data class IdAndVpToken(
        val idTokenType: List<IdTokenType>,
        val presentationQuery: PresentationQuery,
    ) : PresentationType
}

val PresentationType.presentationDefinitionOrNull: PresentationDefinition?
    get() = when (this) {
        is PresentationType.IdTokenRequest -> null
        is PresentationType.VpTokenRequest -> presentationQuery.presentationDefinitionOrNull
        is PresentationType.IdAndVpToken -> presentationQuery.presentationDefinitionOrNull
    }

val PresentationType.dcqlQueryOrNull: DCQL?
    get() = when (this) {
        is PresentationType.IdTokenRequest -> null
        is PresentationType.VpTokenRequest -> presentationQuery.dcqlQueryOrNull
        is PresentationType.IdAndVpToken -> presentationQuery.dcqlQueryOrNull
    }

sealed interface VerifiablePresentation {
    val format: Format

    data class Str(val value: String, override val format: Format) : VerifiablePresentation {
        init {
            require(value.isNotBlank()) { "VpToken cannot be blank" }
        }
    }

    data class Json(val value: JsonObject, override val format: Format) : VerifiablePresentation {
        init {
            require(value.isNotEmpty()) { "VpToken must contain claims" }
        }
    }
}

/**
 * The Wallet's response to a 'vp_token' request.
 */
sealed interface VpContent {

    /**
     * A 'vp_token' response as defined by Presentation Exchange.
     */
    data class PresentationExchange(
        val verifiablePresentations: NonEmptyList<VerifiablePresentation>,
        val presentationSubmission: PresentationSubmission,
    ) : VpContent {
        init {
            require(verifiablePresentations.size == verifiablePresentations.distinct().size)
        }
    }

    /**
     * A 'vp_token' response as defined by DCQL.
     */
    data class DCQL(val verifiablePresentations: Map<QueryId, VerifiablePresentation>) : VpContent {
        init {
            require(verifiablePresentations.isNotEmpty())
        }
    }
}

internal fun VpContent.verifiablePresentations(): List<VerifiablePresentation> =
    when (this) {
        is VpContent.PresentationExchange -> verifiablePresentations
        is VpContent.DCQL -> verifiablePresentations.values.distinct()
    }

internal fun VpContent.presentationSubmissionOrNull(): PresentationSubmission? =
    when (this) {
        is VpContent.PresentationExchange -> presentationSubmission
        is VpContent.DCQL -> null
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
        val vpContent: VpContent,
    ) : WalletResponse

    data class IdAndVpToken(
        val idToken: Jwt,
        val vpContent: VpContent,
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
