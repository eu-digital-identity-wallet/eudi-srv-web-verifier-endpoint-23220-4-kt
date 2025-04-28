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
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.sdjwt.SdJwtVerificationException
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.digest.hash
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.encoding.base64UrlNoPadding
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.SdJwtVcValidationError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.SdJwtVcValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.StatusCheckException
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.description
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(ValidateSdJwtVcOrMsoMdocVerifiablePresentation::class.java)

internal class ValidateSdJwtVcOrMsoMdocVerifiablePresentation(
    private val config: VerifierConfig,
    private val sdJwtVcValidatorFactory: (X5CShouldBe.Trusted?) -> SdJwtVcValidator,
    private val deviceResponseValidatorFactory: (X5CShouldBe.Trusted?) -> DeviceResponseValidator,
) : ValidateVerifiablePresentation {

    override suspend fun invoke(
        transactionId: TransactionId?,
        verifiablePresentation: VerifiablePresentation,
        vpFormat: VpFormat,
        nonce: Nonce,
        transactionData: NonEmptyList<TransactionData>?,
        issuerChain: X5CShouldBe.Trusted?,
    ): Either<WalletResponseValidationError, VerifiablePresentation> = either {
        when (verifiablePresentation.format) {
            Format(SdJwtVcSpec.MEDIA_SUBTYPE_VC_SD_JWT), Format.SdJwtVc -> {
                require(vpFormat is VpFormat.SdJwtVc)
                val validator = sdJwtVcValidatorFactory(issuerChain)
                validator.validateSdJwtVcVerifiablePresentation(
                    vpFormat,
                    verifiablePresentation,
                    nonce,
                    transactionData,
                    transactionId,
                ).bind()
            }

            Format.MsoMdoc -> {
                require(vpFormat is VpFormat.MsoMdoc)
                val validator = deviceResponseValidatorFactory(issuerChain)
                validator.validateMsoMdocVerifiablePresentation(
                    vpFormat,
                    verifiablePresentation,
                ).bind()
            }

            else ->
                throw IllegalArgumentException("unsupported format '${verifiablePresentation.format}'")
        }
    }

    private suspend fun SdJwtVcValidator.validateSdJwtVcVerifiablePresentation(
        vpFormat: VpFormat.SdJwtVc,
        verifiablePresentation: VerifiablePresentation,
        nonce: Nonce,
        transactionData: NonEmptyList<TransactionData>?,
        transactionId: TransactionId?,
    ): Either<WalletResponseValidationError, VerifiablePresentation> = either {
        fun Either<NonEmptyList<SdJwtVcValidationError>, SdJwtAndKbJwt<SignedJWT>>.getOrRaise(): SdJwtAndKbJwt<SignedJWT> =
            fold(
                ifRight = { it },
                ifLeft = { errors ->
                    val validationFailures = jsonSupport.encodeToString(errors.toJson())
                    log.warn("Failed to validate SD-JWT VC: $validationFailures")
                    raise(WalletResponseValidationError.InvalidVpToken(validationFailures))
                },
            )

        val (sdJwt, kbJwt) = when (verifiablePresentation) {
            is VerifiablePresentation.Str -> validate(
                unverified = verifiablePresentation.value,
                nonce = nonce,
                transactionId = transactionId,
            ).getOrRaise()

            is VerifiablePresentation.Json -> validate(
                unverified = verifiablePresentation.value,
                nonce = nonce,
                transactionId = transactionId,
            ).getOrRaise()
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
            ensureValidTransactionDataHashes(kbJwt, transactionData, config.transactionDataHashAlgorithm) { error ->
                WalletResponseValidationError.InvalidVpToken(error)
            }
        }

        verifiablePresentation
    }

    private fun DeviceResponseValidator.validateMsoMdocVerifiablePresentation(
        vpFormat: VpFormat.MsoMdoc,
        verifiablePresentation: VerifiablePresentation,
    ): Either<WalletResponseValidationError, VerifiablePresentation.Str> = either {
        ensure(verifiablePresentation is VerifiablePresentation.Str) {
            WalletResponseValidationError.InvalidVpToken("Mso MDoc VC must be a string.")
        }

        ensureValid(verifiablePresentation.value)
            .fold(
                ifLeft = { error ->
                    log.warn("Failed to validate MsoMdoc VC. Reason: '$error'")
                    raise(error.toWalletResponseValidationError())
                },
                ifRight = { documents ->
                    documents.forEach { document ->
                        val issuerAuth = ensureNotNull(document.issuerSigned.issuerAuth) {
                            WalletResponseValidationError.InvalidVpToken("DeviceResponse contains unsigned MSO MDoc documents")
                        }
                        val algorithm = issuerAuth.algorithm.toJwsAlgorithm().bind()
                        ensure(algorithm in vpFormat.algorithms) {
                            WalletResponseValidationError.InvalidVpToken("MSO MDoc is not signed with a supported algorithms")
                        }
                    }
                    verifiablePresentation
                },
            )
    }
}

private fun JWTClaimsSet.stringClaim(claim: String): Result<String> =
    runCatching {
        getStringClaim(claim)
    }

private fun JWTClaimsSet.stringListClaim(claim: String): Result<List<String>> =
    runCatching {
        getStringListClaim(claim)
    }

private fun <Error> Raise<Error>.ensureValidTransactionDataHashes(
    keyBindingJwt: SignedJWT,
    transactionData: NonEmptyList<TransactionData>,
    hashAlgorithm: HashAlgorithm,
    convert: (String) -> Error,
) {
    val actualHashAlgorithm = keyBindingJwt.jwtClaimsSet.stringClaim("transaction_data_hashes_alg")
        .getOrElse {
            raise(convert(it.message ?: "'transaction_data_hashes_alg' claim is not a string"))
        }
    ensure(hashAlgorithm.ianaName == actualHashAlgorithm) {
        convert("'transaction_data_hashes_alg' must be '${hashAlgorithm.ianaName}'")
    }

    val expectedHashes = transactionData.map {
        val hash = hash(it.base64Url, hashAlgorithm)
        base64UrlNoPadding.encode(hash)
    }
    val actualHashes = keyBindingJwt.jwtClaimsSet.stringListClaim("transaction_data_hashes")
        .getOrElse {
            raise(convert(it.message ?: "'transaction_data_hashes_alg' claim is not a string list"))
        }
    ensure(actualHashes.isNotEmpty() && actualHashes.size <= expectedHashes.size && expectedHashes.containsAll(actualHashes)) {
        convert("hashes of transaction data do not match the expected values")
    }
}

private fun DeviceResponseError.toWalletResponseValidationError(): WalletResponseValidationError.InvalidVpToken {
    val error = when (this) {
        DeviceResponseError.CannotBeDecoded -> "DeviceResponse cannot be decoded"
        is DeviceResponseError.InvalidDocuments -> {
            val deviceResponseErrors = invalidDocuments.joinToString { invalidDocument ->
                val documentErrors = invalidDocument.errors.joinToString()
                "Document at index '${invalidDocument.index}' with docType '${invalidDocument.documentType}' " +
                    "contains the following errors: '$documentErrors'"
            }

            "DeviceResponse contains invalid documents: $deviceResponseErrors"
        }
        is DeviceResponseError.NotOkDeviceResponseStatus -> "Unexpected DeviceResponse status: '$status'"
    }

    return WalletResponseValidationError.InvalidVpToken(error)
}

// Mappings taken from https://www.iana.org/assignments/cose/cose.xhtml#algorithms
private fun Int.toJwsAlgorithm(): Either<WalletResponseValidationError, JWSAlgorithm> = either {
    when (this@toJwsAlgorithm) {
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
        else -> raise(WalletResponseValidationError.InvalidVpToken("Unknown AlgorithmID '${this@toJwsAlgorithm}'"))
    }
}

private fun Collection<SdJwtVcValidationError>.toJson(): JsonArray =
    JsonArray(
        map { error ->
            buildJsonObject {
                put("error", error.reason.name)
                val (description, cause) = when (val cause = error.cause) {
                    is SdJwtVerificationException -> cause.description to null
                    is StatusCheckException -> cause.reason to cause.causedBy
                    else -> "an unexpected error occurred${cause.message?.let { ": $it" } ?: ""}" to cause
                }
                put("description", description)
                cause?.message?.let { put("cause", it) }
            }
        },
    )
