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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.*
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import eu.europa.ec.eudi.sdjwt.SdJwtVerificationException
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.SdJwtVcValidationError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.SdJwtVcValidationErrorCode
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.SdJwtVcValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.StatusCheckException
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.description
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ParsePemEncodedX509Certificate
import kotlinx.serialization.json.*

internal enum class SdJwtVcValidationErrorCodeTO {
    IsUnparsable,
    ContainsInvalidJwt,
    IsMissingHolderPublicKey,
    UnsupportedHolderPublicKey,
    ContainsInvalidKeyBindingJwt,
    ContainsKeyBindingJwt,
    IsMissingKeyBindingJwt,
    ContainsInvalidDisclosures,
    ContainsUnsupportedHashingAlgorithm,
    ContainsNonUniqueDigests,
    ContainsNonUniqueDisclosures,
    ContainsDisclosuresWithNoDigests,
    UnsupportedVerificationMethod,
    UnableToResolveIssuerMetadata,
    IssuerCertificateIsNotTrusted,
    UnableToLookupDID,
    UnableToDetermineVerificationMethod,
    StatusCheckFailed,
    UnexpectedError,
    InvalidTrustedIssuers,
}

internal data class SdJwtVcValidationErrorDetailsTO(
    val reason: SdJwtVcValidationErrorCodeTO,
    val description: String,
    val cause: Throwable?,
)

internal fun SdJwtVcValidationResult.Invalid.toJson(): JsonArray = buildJsonArray {
    errors.forEach { error ->
        addJsonObject {
            put("error", error.reason.name)
            put("description", error.description)
            error.cause?.message?.let { cause -> put("cause", cause) }
        }
    }
}

internal sealed interface SdJwtVcValidationResult {
    /**
     * Successfully validated an SD-JWT Verifiable Credential.
     */
    data class Valid(val payload: SdJwtAndKbJwt<SignedJWT>) : SdJwtVcValidationResult

    /**
     * SD-JWT Verifiable Credential validation failed.
     */
    data class Invalid(val errors: NonEmptyList<SdJwtVcValidationErrorDetailsTO>) : SdJwtVcValidationResult
}

/**
 * Validates an SD-JWT Verifiable Credential.
 */
internal class ValidateSdJwtVc(
    private val sdJwtVcValidatorFactory: (X5CShouldBe.Trusted?) -> SdJwtVcValidator,
    private val parsePemEncodedX509Certificate: ParsePemEncodedX509Certificate,
) {

    suspend operator fun invoke(unverified: JsonObject, nonce: Nonce, trustedIssuers: NonEmptyList<String>?): SdJwtVcValidationResult =
        validate(unverified.left(), nonce, trustedIssuers)

    suspend operator fun invoke(unverified: String, nonce: Nonce, trustedIssuers: NonEmptyList<String>?): SdJwtVcValidationResult =
        validate(unverified.right(), nonce, trustedIssuers)

    private suspend fun validate(
        unverified: Either<JsonObject, String>,
        nonce: Nonce,
        trustedIssuers: NonEmptyList<String>?,
    ): SdJwtVcValidationResult {
        val sdJwtVcValidator = sdJwtVcValidator(trustedIssuers)
            .getOrElse {
                return SdJwtVcValidationResult.Invalid(nonEmptyListOf(it.toInvalidTrustedIssuersSdJwtVcValidationError()))
            }

        return unverified.fold(
            ifLeft = { sdJwtVcValidator.validate(it, nonce, null) },
            ifRight = { sdJwtVcValidator.validate(it, nonce, null) },
        ).fold(
            ifLeft = { errors -> SdJwtVcValidationResult.Invalid(errors.map { it.toSdJwtVcValidationError() }) },
            ifRight = { SdJwtVcValidationResult.Valid(it) },
        )
    }

    private fun sdJwtVcValidator(certificates: NonEmptyList<String>?): Result<SdJwtVcValidator> =
        runCatching {
            val x5cShouldBe = certificates?.map { parsePemEncodedX509Certificate(it).getOrThrow() }
                ?.let {
                    X5CShouldBe.Trusted(it) {
                        isRevocationEnabled = false
                    }
                }
            sdJwtVcValidatorFactory(x5cShouldBe)
        }
}

private fun Throwable.toInvalidTrustedIssuersSdJwtVcValidationError(): SdJwtVcValidationErrorDetailsTO =
    SdJwtVcValidationErrorDetailsTO(
        reason = SdJwtVcValidationErrorCodeTO.InvalidTrustedIssuers,
        description = "unable to parse Trusted Issuers certificates",
        cause = this,
    )

private fun SdJwtVcValidationError.toSdJwtVcValidationError(): SdJwtVcValidationErrorDetailsTO =
    SdJwtVcValidationErrorDetailsTO(
        reason = reason.toSdJwtVcValidationErrorCodeTO(),
        description = when (cause) {
            is SdJwtVerificationException -> cause.description
            is StatusCheckException -> cause.reason
            else -> "an unexpected error occurred${cause.message?.let { ": $it" } ?: ""}"
        },
        cause = cause.cause,
    )

private fun SdJwtVcValidationErrorCode.toSdJwtVcValidationErrorCodeTO(): SdJwtVcValidationErrorCodeTO =
    SdJwtVcValidationErrorCodeTO.valueOf(name)
