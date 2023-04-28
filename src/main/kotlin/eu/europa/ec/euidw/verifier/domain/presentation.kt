package eu.europa.ec.euidw.verifier.domain

import eu.europa.ec.euidw.prex.PresentationDefinition
import java.time.Clock
import java.time.Instant


@JvmInline
value class PresentationId(val value: String){
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
value class RequestId(val value: String){
    init {
        require(value.isNotBlank())
    }
}


typealias Jwt = String

enum class IdTokenType {
    SubjectSigned,
    AttesterSigned
}

/**
 * Represents what the [Presentation] is asking
 * from the wallet
 */
sealed interface PresentationType {
    data class IdTokenRequest(
        val idTokenType: List<IdTokenType>
    ) : PresentationType

    data class VpTokenRequest(
        val presentationDefinition: PresentationDefinition
    ) : PresentationType

    data class IdAndVpToken(
        val idTokenType: List<IdTokenType>,
        val presentationDefinition: PresentationDefinition
    ) : PresentationType
}

val PresentationType.presentationDefinitionOrNull: PresentationDefinition?
    get() = when (this) {
        is PresentationType.IdTokenRequest -> null
        is PresentationType.VpTokenRequest -> presentationDefinition
        is PresentationType.IdAndVpToken -> presentationDefinition
    }

/**
 * The entity that represents the presentation process
 */
sealed interface Presentation {
    val id: PresentationId
    val initiatedAt: Instant
    val type: PresentationType

    /**
     * A presentation process that has been just requested
     */
    class Requested(
        override val id: PresentationId,
        override val initiatedAt: Instant,
        override val type: PresentationType,
        val requestId: RequestId
    ) : Presentation

    /**
     * A presentation process for which the wallet has obtained the request object
     * Depending on the configuration of the verifier this can be done
     * as part of the initialization of the process (when using request JAR parameter)
     * or later on (when using request_uri JAR parameter)
     */
    class RequestObjectRetrieved private constructor(
        override val id: PresentationId,
        override val initiatedAt: Instant,
        override val type: PresentationType,
        val requestId: RequestId,
        val requestObjectRetrievedAt: Instant
    ) : Presentation {
        init {
            require(initiatedAt.isBefore(requestObjectRetrievedAt) || initiatedAt == requestObjectRetrievedAt)
        }

        companion object {
            fun requestObjectRetrieved(requested: Requested, at: Instant): Result<RequestObjectRetrieved> =
                runCatching {
                    RequestObjectRetrieved(requested.id, requested.initiatedAt, requested.type, requested.requestId, at)
                }
        }
    }

    class TimedOut private constructor(
        override val id: PresentationId,
        override val initiatedAt: Instant,
        override val type: PresentationType,
        val requestObjectRetrievedAt: Instant? = null,
        val timedOutAt: Instant
    ) : Presentation {
        companion object {
            fun timeOut(presentation: Requested, at: Instant): Result<TimedOut> = runCatching {
                require(presentation.initiatedAt.isBefore(at))
                TimedOut(presentation.id, presentation.initiatedAt, presentation.type, null, at)
            }

            fun timeOut(presentation: RequestObjectRetrieved, at: Instant): Result<TimedOut> = runCatching {
                require(presentation.initiatedAt.isBefore(at))
                TimedOut(
                    presentation.id,
                    presentation.initiatedAt,
                    presentation.type,
                    presentation.requestObjectRetrievedAt,
                    at
                )
            }
        }
    }
}



fun Presentation.Requested.retrieveRequestObject(clock: Clock): Result<Presentation.RequestObjectRetrieved> =
    Presentation.RequestObjectRetrieved.requestObjectRetrieved(this, clock.instant())

fun Presentation.Requested.timedOut(clock: Clock): Result<Presentation.TimedOut> =
    Presentation.TimedOut.timeOut(this, clock.instant())

