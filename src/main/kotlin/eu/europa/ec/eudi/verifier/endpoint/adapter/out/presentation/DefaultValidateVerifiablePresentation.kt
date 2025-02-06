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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.presentation

import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.RFC7519
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerifier
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.domain.Format
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifiablePresentation
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierId
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(DefaultValidateVerifiablePresentation::class.java)

internal class DefaultValidateVerifiablePresentation(
    private val verifierId: VerifierId,
    private val sdJwtVcVerifier: SdJwtVcVerifier<SignedJWT>,
    private val deviceResponseValidator: DeviceResponseValidator,
) : ValidateVerifiablePresentation {

    override suspend fun invoke(
        verifiablePresentation: VerifiablePresentation,
        nonce: Nonce,
    ): Result<VerifiablePresentation> = runCatching {
        when (verifiablePresentation.format) {
            Format(SdJwtVcSpec.MEDIA_SUBTYPE_VC_SD_JWT), Format.SdJwtVc -> {
                val challenge = buildJsonObject {
                    put(RFC7519.AUDIENCE, verifierId.clientId)
                    put("nonce", nonce.value)
                }

                when (verifiablePresentation) {
                    is VerifiablePresentation.Str -> {
                        sdJwtVcVerifier.verify(unverifiedSdJwt = verifiablePresentation.value, challenge = challenge)
                            .fold(
                                onSuccess = { verifiablePresentation },
                                onFailure = {
                                    log.warn("Failed to validate SD-JWT VC", it)
                                    throw IllegalArgumentException("Invalid SdJwtVc", it)
                                },
                            )
                    }

                    is VerifiablePresentation.Json -> {
                        sdJwtVcVerifier.verify(unverifiedSdJwt = verifiablePresentation.value, challenge = challenge)
                            .fold(
                                onSuccess = { verifiablePresentation },
                                onFailure = {
                                    log.warn("Failed to validate SD-JWT VC", it)
                                    throw IllegalArgumentException("Invalid SdJwtVc", it)
                                },
                            )
                    }
                }
            }

            Format.MsoMdoc -> {
                require(verifiablePresentation is VerifiablePresentation.Str)
                deviceResponseValidator.ensureValid(verifiablePresentation.value)
                    .fold(
                        ifLeft = {
                            log.warn("Failed to validate MsoMdoc VC. Reason: '$it'")
                            throw IllegalArgumentException("Invalid MsoMdoc DeviceResponse: '$it'")
                        },
                        ifRight = { verifiablePresentation },
                    )
            }

            else -> verifiablePresentation
        }
    }
}
