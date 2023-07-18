/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.prex.PresentationExchange
import eu.europa.ec.eudi.verifier.endpoint.domain.Jwt
import eu.europa.ec.eudi.verifier.endpoint.port.input.AuthorisationResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyJarmJwtSignature

object VerifyJarmJwtSignatureNimbus : VerifyJarmJwtSignature {

    override fun invoke(jarmJwt: Jwt, signAlg: JWSAlgorithm?, encAlg: JWEAlgorithm?, encMethod: EncryptionMethod?):
        Result<AuthorisationResponseTO> = runCatching {
        SignedJWT.parse(jarmJwt).jwtClaimsSet.mapToDomain()
    }

    private fun JWTClaimsSet.mapToDomain(): AuthorisationResponseTO =
        AuthorisationResponseTO(
            state = getClaim("state")?.toString(),
            idToken = getClaim("id_token")?.toString(),
            vpToken = getClaim("vp_token")?.toString(),
            presentationSubmission = getClaim("presentation_submission")?.let {
                PresentationExchange.jsonParser.decodePresentationSubmission(it.toString()).getOrThrow()
            },
            error = getClaim("error")?.toString(),
            errorDescription = getClaim("error_description")?.toString(),
        )
}
