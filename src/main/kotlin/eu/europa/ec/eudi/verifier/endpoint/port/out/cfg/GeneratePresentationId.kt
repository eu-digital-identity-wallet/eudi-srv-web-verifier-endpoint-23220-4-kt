package eu.europa.ec.eudi.verifier.endpoint.port.out.cfg

import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationId

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