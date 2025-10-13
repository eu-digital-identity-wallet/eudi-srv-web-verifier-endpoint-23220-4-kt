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

import arrow.core.Either
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTProcessor
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.AuthorisationResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyEncryptedResponse
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Decrypts an encrypted JWT and maps the JWT claimSet to an AuthorisationResponseTO
 */
class VerifyEncryptedResponseWithNimbus(
    private val responseEncryptionOption: ResponseEncryptionOption,
) : VerifyEncryptedResponse {

    private val logger: Logger = LoggerFactory.getLogger(VerifyEncryptedResponseWithNimbus::class.java)

    override fun invoke(
        ephemeralResponseEncryptionKey: JWK,
        encryptedResponse: Jwt,
        apv: Nonce,
    ): Either<Throwable, AuthorisationResponseTO> = Either.catch {
        val processor = encryptedProcessor(responseEncryptionOption, ephemeralResponseEncryptionKey)
        val jwt = JWTParser.parse(encryptedResponse)
        val claimSet = processor.process(jwt, null)
        claimSet.mapToDomain()
    }

    private fun encryptedProcessor(
        encrypt: ResponseEncryptionOption,
        ephemeralResponseEncryptionKey: JWK,
    ): JWTProcessor<SecurityContext> = DefaultJWTProcessor<SecurityContext>().apply {
        jweKeySelector = JWEDecryptionKeySelector(
            encrypt.algorithm,
            encrypt.encryptionMethod,
            ImmutableJWKSet(JWKSet(ephemeralResponseEncryptionKey)),
        )
    }

    @Suppress("UNCHECKED_CAST")
    private fun JWTClaimsSet.mapToDomain(): AuthorisationResponseTO =
        AuthorisationResponseTO(
            state = getClaim(RFC6749.STATE)?.toString(),
            vpToken = getJSONObjectClaim(OpenId4VPSpec.VP_TOKEN)
                ?.let { vpToken ->
                    Json.decodeFromString<JsonObject>(JSONObjectUtils.toJSONString(vpToken))
                },
            error = getClaim(RFC6749.ERROR)?.toString(),
            errorDescription = getClaim(RFC6749.ERROR_DESCRIPTION)?.toString(),
        )
}
