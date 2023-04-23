package eu.europa.ec.euidw.verifier.application.port.out.jose

import eu.europa.ec.euidw.verifier.domain.Jwt
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.VerifierConfig
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