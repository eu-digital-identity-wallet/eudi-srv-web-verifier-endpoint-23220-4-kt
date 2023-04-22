package eu.europa.ec.euidw.verifier.application.port.out.cfg

import eu.europa.ec.euidw.verifier.domain.RequestId

/**
 * A port for generating [RequestId]
 */
fun interface GenerateRequestId {
    suspend operator fun invoke(): RequestId

    companion object {

        /**
         * Fixed generator, useful in tests
         */
        fun fixed(id: RequestId): GenerateRequestId = GenerateRequestId { id }
    }
}