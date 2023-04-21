package eu.europa.ec.euidw.verifier.application.port.out

import eu.europa.ec.euidw.verifier.domain.PresentationId
import java.util.*

/**
 * A port for generating [PresentationId]
 */
fun interface GeneratePresentationId {
    suspend operator fun invoke(): PresentationId

    companion object {
        /**
         * Random generator
         */
        val random: GeneratePresentationId by lazy {
            GeneratePresentationId { PresentationId(UUID.randomUUID()) }
        }

        /**
         * Fixed generator, useful in tests
         */
        fun fixed(id: PresentationId) : GeneratePresentationId =
            GeneratePresentationId { id }
    }
}