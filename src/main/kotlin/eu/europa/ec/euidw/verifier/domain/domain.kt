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
sealed interface PresentationType {
    data class IdTokenRequest(val idTokenType: List<IdTokenType>) : PresentationType
    data class VpTokenRequest(val presentationDefinition: PresentationDefinition) : PresentationType
    data class IdAndVpToken(val idTokenType: List<IdTokenType>, val presentationDefinition: PresentationDefinition) :
        PresentationType
}


sealed interface Presentation {
    val id: PresentationId
    val initiatedAt: Instant
    val type: PresentationType

    class Requested(
        override val id: PresentationId,
        override val initiatedAt: Instant,
        override val type: PresentationType,
    ) : Presentation


    class TimedOut private constructor(
        override val id: PresentationId,
        override val initiatedAt: Instant,
        override val type: PresentationType,
        val timedOutAt: Instant
    ) : Presentation {
        companion object {
            fun timeOut(requested: Requested, at: Instant): Result<TimedOut> = runCatching {
                require(requested.initiatedAt.isBefore(at))
                TimedOut(requested.id, requested.initiatedAt, requested.type, at)
            }
        }
    }
}

fun Presentation.Requested.timedOut(at: Instant): Result<Presentation.TimedOut> =
    Presentation.TimedOut.timeOut(this, at)

