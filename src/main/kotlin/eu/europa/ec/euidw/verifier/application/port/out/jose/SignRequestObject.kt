package eu.europa.ec.euidw.verifier.application.port.out.jose

import eu.europa.ec.euidw.verifier.domain.Jwt
import eu.europa.ec.euidw.verifier.application.port.`in`.RequestObject


fun interface SignRequestObject {
    operator fun invoke(requestObject: RequestObject): Result<Jwt>
}