package eu.europa.ec.euidw.verifier.application.port.out

import eu.europa.ec.euidw.verifier.domain.PresentationId
import java.util.*

fun interface GeneratePresentationId {
    suspend operator fun invoke(): PresentationId

    companion object {
        val live: GeneratePresentationId by lazy {
            GeneratePresentationId { PresentationId(UUID.randomUUID()) }
        }
    }
}