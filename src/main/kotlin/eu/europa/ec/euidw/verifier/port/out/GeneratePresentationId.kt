package eu.europa.ec.euidw.verifier.port.out

import eu.europa.ec.euidw.verifier.PresentationId
import java.util.*

fun interface GeneratePresentationId {
    suspend fun invoke(): PresentationId

    companion object {
        val live: GeneratePresentationId by lazy {
            GeneratePresentationId { PresentationId(UUID.randomUUID()) }
        }
    }
}