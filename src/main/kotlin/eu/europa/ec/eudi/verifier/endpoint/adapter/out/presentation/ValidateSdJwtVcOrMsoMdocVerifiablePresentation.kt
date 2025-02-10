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
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.digest.hash
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.encoding.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.domain.Format
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifiablePresentation
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import kotlinx.io.bytestring.encode
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(ValidateSdJwtVcOrMsoMdocVerifiablePresentation::class.java)

internal class ValidateSdJwtVcOrMsoMdocVerifiablePresentation(
    private val config: VerifierConfig,
    private val sdJwtVcVerifier: SdJwtVcVerifier<SignedJWT>,
    private val deviceResponseValidator: DeviceResponseValidator,
) : ValidateVerifiablePresentation {

    override suspend fun invoke(
        verifiablePresentation: VerifiablePresentation,
        nonce: Nonce,
        transactionData: List<JsonObject>?,
    ): Result<VerifiablePresentation> = runCatching {
        when (verifiablePresentation.format) {
            Format(SdJwtVcSpec.MEDIA_SUBTYPE_VC_SD_JWT), Format.SdJwtVc -> {
                val challenge = buildJsonObject {
                    put(RFC7519.AUDIENCE, config.verifierId.clientId)
                    put("nonce", nonce.value)
                    transactionData?.let { transactionData ->
                        putJsonArray("transaction_data_hashes") {
                            transactionData.forEach {
                                val serialized = Json.encodeToString(it)
                                val base64 = base64UrlNoPadding.encode(serialized.encodeToByteString())
                                val hash = hash(base64, config.transactionDataHashAlgorithm)
                                val base64Hash = base64UrlNoPadding.encode(hash)
                                add(base64Hash)
                            }
                        }

                        put("transaction_data_hashes_alg", config.transactionDataHashAlgorithm.ianaName)
                    }
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
