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

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.raise.either
import arrow.core.raise.ensure
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.digest.hash
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.encoding.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.SdJwtVcValidationResult
import eu.europa.ec.eudi.verifier.endpoint.port.input.ValidateSdJwtVc
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError
import eu.europa.ec.eudi.verifier.endpoint.port.input.toJson
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(ValidateSdJwtVcOrMsoMdocVerifiablePresentation::class.java)

internal class ValidateSdJwtVcOrMsoMdocVerifiablePresentation(
    private val config: VerifierConfig,
    private val deviceResponseValidator: DeviceResponseValidator,
    private val validateSdJwtVc: ValidateSdJwtVc,
) : ValidateVerifiablePresentation {

    override suspend fun invoke(
        transactionId: TransactionId?,
        verifiablePresentation: VerifiablePresentation,
        vpFormat: VpFormat,
        nonce: Nonce,
        transactionData: NonEmptyList<TransactionData>?,
    ): Either<WalletResponseValidationError, VerifiablePresentation> = either {
        when (verifiablePresentation.format) {
            Format(SdJwtVcSpec.MEDIA_SUBTYPE_VC_SD_JWT), Format.SdJwtVc -> {
                require(vpFormat is VpFormat.SdJwtVc)
                validateSdJwtVcVerifiablePresentation(vpFormat, verifiablePresentation, nonce, transactionData, transactionId).bind()
            }

            Format.MsoMdoc -> {
                require(vpFormat is VpFormat.MsoMdoc)
                validateMsoMdocVerifiablePresentation(vpFormat, verifiablePresentation)
            }

            else ->
                throw IllegalArgumentException("unsupported format '${verifiablePresentation.format}'")
        }
    }

    private suspend fun validateSdJwtVcVerifiablePresentation(
        vpFormat: VpFormat.SdJwtVc,
        verifiablePresentation: VerifiablePresentation,
        nonce: Nonce,
        transactionData: NonEmptyList<TransactionData>?,
        transactionId: TransactionId?,
    ): Either<WalletResponseValidationError, VerifiablePresentation> = either {
        fun SdJwtVcValidationResult.get(): SdJwtAndKbJwt<SignedJWT> =
            when (this) {
                is SdJwtVcValidationResult.Valid -> this.payload
                is SdJwtVcValidationResult.Invalid -> {
                    val validationFailures = this.toJson().toString()
                    log.warn("Failed to validate SD-JWT VC: $validationFailures")
                    raise(WalletResponseValidationError.InvalidVpToken(validationFailures))
                }
            }

        val (sdJwt, kbJwt) = when (verifiablePresentation) {
            is VerifiablePresentation.Str -> validateSdJwtVc(
                unverified = verifiablePresentation.value,
                nonce = nonce,
                transactionId = transactionId,
            ).get()

            is VerifiablePresentation.Json -> validateSdJwtVc(
                unverified = verifiablePresentation.value,
                nonce = nonce,
                transactionId = transactionId,
            ).get()
        }

        // Validate that the signing algorithm of sd-jwt-vc matches the algorithm specified in the presentation query
        ensure(sdJwt.jwt.header.algorithm in vpFormat.sdJwtAlgorithms) {
            WalletResponseValidationError.InvalidVpToken("SD-JWT not signed with a supported algorithm")
        }
        // Validate that the signing algorithm of key binding JWT matches the algorithm specified in the presentation query
        ensure(kbJwt.header.algorithm in vpFormat.kbJwtAlgorithms) {
            WalletResponseValidationError.InvalidVpToken("Keybinding JWT not signed with a supported algorithm")
        }

        transactionData?.let {
            validateTransactionDataHashes(kbJwt, transactionData, config.transactionDataHashAlgorithm)
        }

        verifiablePresentation
    }

    private fun validateMsoMdocVerifiablePresentation(
        vpFormat: VpFormat.MsoMdoc,
        verifiablePresentation: VerifiablePresentation,
    ): VerifiablePresentation.Str {
        require(verifiablePresentation is VerifiablePresentation.Str)
        return deviceResponseValidator.ensureValid(verifiablePresentation.value)
            .fold(
                ifLeft = {
                    log.warn("Failed to validate MsoMdoc VC. Reason: '$it'")
                    throw IllegalArgumentException("Invalid MsoMdoc DeviceResponse: '$it'")
                },
                ifRight = { documents ->
                    documents.forEach {
                        val algorithm = requireNotNull(it.issuerSigned.issuerAuth?.algorithm?.toJwsAlgorithm()) {
                            "MSO MDoc is not signed"
                        }
                        require(algorithm in vpFormat.algorithms) {
                            "MSO MDoc is not signed with a supported algorithms"
                        }
                    }
                    verifiablePresentation
                },
            )
    }
}

private fun validateTransactionDataHashes(
    keyBindingJwt: SignedJWT,
    transactionData: NonEmptyList<TransactionData>,
    hashAlgorithm: HashAlgorithm,
) {
    val actualHashAlgorithm = keyBindingJwt.jwtClaimsSet.getStringClaim("transaction_data_hashes_alg")
    require(hashAlgorithm.ianaName == actualHashAlgorithm) {
        "'transaction_data_hashes_alg' must be '${hashAlgorithm.ianaName}'"
    }

    val expectedHashes = transactionData.map {
        val hash = hash(it.base64Url, hashAlgorithm)
        base64UrlNoPadding.encode(hash)
    }
    val actualHashes = keyBindingJwt.jwtClaimsSet.getStringListClaim("transaction_data_hashes")
    require(actualHashes.isNotEmpty() && actualHashes.size <= expectedHashes.size && expectedHashes.containsAll(actualHashes)) {
        "hashes of transaction data do not match the expected values"
    }
}

// Mappings taken from https://www.iana.org/assignments/cose/cose.xhtml#algorithms
private fun Int.toJwsAlgorithm(): JWSAlgorithm =
    when (this) {
        5 -> JWSAlgorithm.HS256
        6 -> JWSAlgorithm.HS384
        7 -> JWSAlgorithm.HS512
        -257 -> JWSAlgorithm.RS256
        -258 -> JWSAlgorithm.RS384
        -259 -> JWSAlgorithm.RS512
        -7 -> JWSAlgorithm.ES256
        -47 -> JWSAlgorithm.ES256K
        -35 -> JWSAlgorithm.ES384
        -36 -> JWSAlgorithm.ES512
        -37 -> JWSAlgorithm.PS256
        -38 -> JWSAlgorithm.PS384
        -39 -> JWSAlgorithm.PS512
        -8 -> JWSAlgorithm.EdDSA
        else -> throw IllegalArgumentException("Unknown AlgorithmID '$this'")
    }
