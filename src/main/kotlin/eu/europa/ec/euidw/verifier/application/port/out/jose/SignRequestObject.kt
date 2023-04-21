package eu.europa.ec.euidw.verifier.application.port.out.jose

import eu.europa.ec.euidw.verifier.application.port.`in`.VerifierConfig
import eu.europa.ec.euidw.verifier.domain.Jwt
import eu.europa.ec.euidw.verifier.domain.Presentation

/**
 * An out port that signs a [Presentation.Requested]
 */
fun interface SignRequestObject {
    operator fun invoke(verifierConfig: VerifierConfig, presentation: Presentation.Requested): Result<Jwt>
}