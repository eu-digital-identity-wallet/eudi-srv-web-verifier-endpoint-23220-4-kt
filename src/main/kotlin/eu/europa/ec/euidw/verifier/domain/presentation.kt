package eu.europa.ec.euidw.verifier.domain

import eu.europa.ec.euidw.prex.PresentationDefinition
import java.time.Instant
import java.util.*


@JvmInline
value class PresentationId(val value: UUID)


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
        val requestObjectRetrievedAt: Instant
    ) : Presentation {
        init {
            require(initiatedAt.isBefore(requestObjectRetrievedAt) || initiatedAt == requestObjectRetrievedAt)
        }
        companion object {
            fun requestObjectRetrieved(requested: Requested, at: Instant): Result<RequestObjectRetrieved> =
                runCatching {
                    RequestObjectRetrieved(requested.id, requested.initiatedAt, requested.type, at)
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

fun Presentation.Requested.retrieveRequestObject(at: Instant): Result<Presentation.RequestObjectRetrieved> =
    Presentation.RequestObjectRetrieved.requestObjectRetrieved(this, at)

fun Presentation.Requested.timedOut(at: Instant): Result<Presentation.TimedOut> =
    Presentation.TimedOut.timeOut(this, at)

