package eu.europa.ec.euidw.verifier.port.out

import eu.europa.ec.euidw.verifier.Jwt
import eu.europa.ec.euidw.verifier.port.`in`.RequestObject


fun interface SignRequestObject {
    operator fun invoke(requestObject: RequestObject): Result<Jwt>
}