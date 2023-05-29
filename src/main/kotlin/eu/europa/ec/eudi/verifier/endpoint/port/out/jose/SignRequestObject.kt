package eu.europa.ec.eudi.verifier.endpoint.port.out.jose

import eu.europa.ec.eudi.verifier.endpoint.domain.Jwt
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import java.time.Clock

/**
 * An out port that signs a [Presentation.Requested]
 */
fun interface SignRequestObject {
    operator fun invoke(
        verifierConfig: VerifierConfig,
        clock: Clock,
        presentation: Presentation.Requested
    ): Result<Jwt>
}