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

import arrow.core.Either
import arrow.core.NonEmptyList
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.serializer.InstantSerializer
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.serializer.TransactionDataNonEmptyListSerializer
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.serializer.X509CertificateNonEmptyListSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant

@JvmInline
@Serializable
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
@Serializable
value class RequestId(val value: String) {
    init {
        require(value.isNotBlank())
    }
}

@JvmInline
@Serializable
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
@Serializable
sealed interface PresentationType {
    @Serializable
    data class IdTokenRequest(
        val idTokenType: List<IdTokenType>,
    ) : PresentationType

    @Serializable
    data class VpTokenRequest(
        val query: DCQL,
        @Serializable(with = TransactionDataNonEmptyListSerializer::class)
        val transactionData: NonEmptyList<TransactionData>?,
    ) : PresentationType

    @Serializable
    data class IdAndVpToken(
        val idTokenType: List<IdTokenType>,
        val query: DCQL,
        @Serializable(with = TransactionDataNonEmptyListSerializer::class)
        val transactionData: NonEmptyList<TransactionData>?,
    ) : PresentationType
}

val PresentationType.queryOrNull: DCQL?
    get() = when (this) {
        is PresentationType.IdTokenRequest -> null
        is PresentationType.VpTokenRequest -> query
        is PresentationType.IdAndVpToken -> query
    }

val PresentationType.transactionDataOrNull: NonEmptyList<TransactionData>?
    get() = when (this) {
        is PresentationType.IdTokenRequest -> null
        is PresentationType.VpTokenRequest -> transactionData
        is PresentationType.IdAndVpToken -> transactionData
    }

@Serializable
sealed interface VerifiablePresentation {
    val format: Format

    @Serializable
    data class Str(val value: String, override val format: Format) : VerifiablePresentation {
        init {
            require(value.isNotBlank()) { "VpToken cannot be blank" }
        }
    }

    @Serializable
    data class Json(val value: JsonObject, override val format: Format) : VerifiablePresentation {
        init {
            require(value.isNotEmpty()) { "VpToken must contain claims" }
        }
    }
}

/**
 * The Wallet's response to a 'vp_token' request.
 */
@JvmInline
@Serializable
value class VerifiablePresentations(val value: Map<QueryId, List<VerifiablePresentation>>) {
    init {
        require(value.isNotEmpty())
        require(value.values.all { it.isNotEmpty() })
    }
}

@Serializable
sealed interface WalletResponse {

    @Serializable
    data class IdToken(
        val idToken: Jwt,
    ) : WalletResponse {
        init {
            require(idToken.isNotEmpty())
        }
    }

    @Serializable
    data class VpToken(
        val verifiablePresentations: VerifiablePresentations,
    ) : WalletResponse

    @Serializable
    data class IdAndVpToken(
        val idToken: Jwt,
        val verifiablePresentations: VerifiablePresentations,
    ) : WalletResponse {
        init {
            require(idToken.isNotEmpty())
        }
    }

    @Serializable
    data class Error(val value: String, val description: String?) : WalletResponse
}

@JvmInline
@Serializable
value class ResponseCode(val value: String)

@Serializable
sealed interface GetWalletResponseMethod {
    @Serializable
    data object Poll : GetWalletResponseMethod

    @Serializable
    data class Redirect(val redirectUriTemplate: String) : GetWalletResponseMethod
}

/**
 * The entity that represents the presentation process
 */
@Serializable
sealed interface Presentation {
    val id: TransactionId
    val initiatedAt: Instant
    val type: PresentationType

    /**
     * A presentation process that has been just requested
     */
    @Serializable
    class Requested(
        override val id: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val initiatedAt: Instant,
        override val type: PresentationType,
        val requestId: RequestId,
        val requestUriMethod: RequestUriMethod,
        val nonce: Nonce,
        val responseMode: ResponseMode,
        val getWalletResponseMethod: GetWalletResponseMethod,
        @Serializable(with = X509CertificateNonEmptyListSerializer::class)
        val issuerChain: NonEmptyList<X509Certificate>?
    ) : Presentation

    /**
     * A presentation process for which the wallet has obtained the request object.
     * Depending on the configuration of the verifier, this can be done
     * as part of the initialization of the process (when using request JAR parameter)
     * or later on (when using request_uri JAR parameter)
     */
    @Serializable
    class RequestObjectRetrieved private constructor(
        override val id: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val initiatedAt: Instant,
        override val type: PresentationType,
        val requestId: RequestId,
        @Serializable(with = InstantSerializer::class)
        val requestObjectRetrievedAt: Instant,
        val nonce: Nonce,
        val responseMode: ResponseMode,
        val getWalletResponseMethod: GetWalletResponseMethod,
        @Serializable(with = X509CertificateNonEmptyListSerializer::class)
        val issuerChain: NonEmptyList<X509Certificate>?,
    ) : Presentation {
        init {
            require(initiatedAt.isBefore(requestObjectRetrievedAt) || initiatedAt == requestObjectRetrievedAt)
        }

        companion object {
            fun requestObjectRetrieved(requested: Requested, at: Instant): Either<Throwable, RequestObjectRetrieved> =
                Either.catch {
                    RequestObjectRetrieved(
                        requested.id,
                        requested.initiatedAt,
                        requested.type,
                        requested.requestId,
                        at,
                        requested.nonce,
                        requested.responseMode,
                        requested.getWalletResponseMethod,
                        requested.issuerChain,
                    )
                }
        }
    }

    /**
     * A presentation process that has been just submitted by the wallet to the verifier backend
     */
    @Serializable
    class Submitted private constructor(
        override val id: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val initiatedAt: Instant,
        override val type: PresentationType,
        val requestId: RequestId,
        @Serializable(with = InstantSerializer::class)
        var requestObjectRetrievedAt: Instant,
        @Serializable(with = InstantSerializer::class)
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
            ): Either<Throwable, Submitted> = Either.catch {
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

    @Serializable
    class TimedOut private constructor(
        override val id: TransactionId,
        @Serializable(with = InstantSerializer::class)
        override val initiatedAt: Instant,
        override val type: PresentationType,
        @Serializable(with = InstantSerializer::class)
        val requestObjectRetrievedAt: Instant? = null,
        @Serializable(with = InstantSerializer::class)
        val submittedAt: Instant? = null,
        @Serializable(with = InstantSerializer::class)
        val timedOutAt: Instant,
    ) : Presentation {
        companion object {
            fun timeOut(presentation: Requested, at: Instant): Either<Throwable, TimedOut> = Either.catch {
                require(presentation.initiatedAt.isBefore(at))
                TimedOut(presentation.id, presentation.initiatedAt, presentation.type, null, null, at)
            }

            fun timeOut(presentation: RequestObjectRetrieved, at: Instant): Either<Throwable, TimedOut> = Either.catch {
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

            fun timeOut(presentation: Submitted, at: Instant): Either<Throwable, TimedOut> = Either.catch {
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

fun Presentation.Requested.retrieveRequestObject(clock: Clock): Either<Throwable, Presentation.RequestObjectRetrieved> =
    Presentation.RequestObjectRetrieved.requestObjectRetrieved(this, clock.instant())

fun Presentation.Requested.timedOut(clock: Clock): Either<Throwable, Presentation.TimedOut> =
    Presentation.TimedOut.timeOut(this, clock.instant())

fun Presentation.RequestObjectRetrieved.timedOut(clock: Clock): Either<Throwable, Presentation.TimedOut> =
    Presentation.TimedOut.timeOut(this, clock.instant())

fun Presentation.RequestObjectRetrieved.submit(
    clock: Clock,
    walletResponse: WalletResponse,
    responseCode: ResponseCode?,
): Either<Throwable, Presentation.Submitted> =
    Presentation.Submitted.submitted(this, clock.instant(), walletResponse, responseCode)

fun Presentation.Submitted.timedOut(clock: Clock): Either<Throwable, Presentation.TimedOut> =
    Presentation.TimedOut.timeOut(this, clock.instant())
