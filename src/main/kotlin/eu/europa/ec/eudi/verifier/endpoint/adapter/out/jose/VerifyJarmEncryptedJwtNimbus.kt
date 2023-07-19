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

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.prex.PresentationExchange
import eu.europa.ec.eudi.verifier.endpoint.domain.EphemeralEncryptionKeyPairJWK
import eu.europa.ec.eudi.verifier.endpoint.domain.Jwt
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import eu.europa.ec.eudi.verifier.endpoint.port.input.AuthorisationResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyJarmJwtSignature
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Decrypts an encrypted JWT and maps the JWT claimSet to an AuthorisationResponseTO
 */
object VerifyJarmEncryptedJwtNimbus : VerifyJarmJwtSignature {

    private val logger: Logger = LoggerFactory.getLogger(VerifyJarmEncryptedJwtNimbus::class.java)

    override fun invoke(
        verifierConfig: VerifierConfig,
        jarmJwt: Jwt,
        ephemeralEcPrivateKey: EphemeralEncryptionKeyPairJWK,
        state: String?,
    ): Result<AuthorisationResponseTO> = runCatching {
        // jwe algorithm to use to decrypt
        val jweAlgorithm = JWEAlgorithm.parse(verifierConfig.clientMetaData.authorizationEncryptedResponseAlg)
        logger.debug("jweAlgorithm: ${jweAlgorithm.name}")

        val privateJwk = ephemeralEcPrivateKey.jwk().toJSONString()
        logger.debug("privateJwk: $privateJwk")
        val ecPrivateKey = ECKey.parse(privateJwk)

        // decrypt JARM
        val jwt = EncryptedJWT.parse(jarmJwt)
        val ecdhDecrypter = ECDHDecrypter(ecPrivateKey)
        jwt.decrypt(ecdhDecrypter)

        jwt.jwtClaimsSet.mapToDomain()
    }

    private fun JWTClaimsSet.mapToDomain(): AuthorisationResponseTO =
        AuthorisationResponseTO(
            state = getClaim("state")?.toString(),
            idToken = getClaim("id_token")?.toString(),
            vpToken = getClaim("vp_token")?.toString(),
            presentationSubmission = getStringClaim("presentation_submission")?.let {
                logger.debug("presentation_submission: $it")
                PresentationExchange.jsonParser.decodePresentationSubmission(it).getOrThrow()
            },
            error = getClaim("error")?.toString(),
            errorDescription = getClaim("error_description")?.toString(),
        )
}
