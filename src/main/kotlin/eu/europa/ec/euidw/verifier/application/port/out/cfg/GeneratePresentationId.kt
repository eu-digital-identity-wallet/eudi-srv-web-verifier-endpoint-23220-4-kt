package eu.europa.ec.euidw.verifier.application.port.out.cfg

import eu.europa.ec.euidw.verifier.domain.PresentationId

/**
 * A port for generating [PresentationId]
 */
fun interface GeneratePresentationId {
    suspend operator fun invoke(): PresentationId

    companion object {

        /**
         * Fixed generator, useful in tests
         */
        fun fixed(id: PresentationId): GeneratePresentationId = GeneratePresentationId { id }
    }
}