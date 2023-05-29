package eu.europa.ec.eudi.verifier.endpoint.port.out.cfg

import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId

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