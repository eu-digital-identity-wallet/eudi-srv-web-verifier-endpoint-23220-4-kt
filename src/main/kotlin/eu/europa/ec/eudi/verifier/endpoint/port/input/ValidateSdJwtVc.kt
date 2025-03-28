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

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps.HolderPubKeyInConfirmationClaim
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps.mustBePresentAndValid
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerificationError
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerificationError.IssuerKeyVerificationError
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerifier
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.description
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.slf4j.LoggerFactory

/**
 * Reasons why validation of an SD-JWT Verifiable Credential might fail.
 */
@Serializable
enum class SdJwtVcValidationErrorTO {
    IsUnparsable,
    ContainsInvalidJwt,

    IsMissingHolderPublicKey,
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

    UnexpectedError,
}

data class SdJwtVcValidationError(
    val reason: SdJwtVcValidationErrorTO,
    val description: String,
    val cause: Throwable?,
)

sealed interface SdJwtVcValidationResult {
    /**
     * Successfully validated an SD-JWT Verifiable Credential.
     */
    data class Valid(val payload: JsonObject) : SdJwtVcValidationResult

    /**
     * SD-JWT Verifiable Credential validation failed.
     */
    data class Invalid(val errors: NonEmptyList<SdJwtVcValidationError>) : SdJwtVcValidationResult
}

internal typealias SdJwt = String
internal typealias Audience = String

private object Claims {
    val Audience = RFC7519.AUDIENCE
    val Nonce = "nonce"
}

private val log = LoggerFactory.getLogger(ValidateSdJwtVc::class.java)

/**
 * Validates an SD-JWT Verifiable Credential.
 *
 * @param sdJwtVcVerifier SdJwtVcVerifier used for verification
 * @param audience the Client Id of this Verifier, expected to be found in the KeyBinding JWT
 */
internal class ValidateSdJwtVc(
    private val sdJwtVcVerifier: SdJwtVcVerifier<SignedJWT>,
    private val audience: Audience,
) {
    private val sdJwtVcNoSignatureVerification: JwtSignatureVerifier<SignedJWT> by lazy {
        val typeVerifier = DefaultJOSEObjectTypeVerifier<SecurityContext>(
            JOSEObjectType(SdJwtVcSpec.MEDIA_SUBTYPE_VC_SD_JWT),
            JOSEObjectType(SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT),
        )
        val claimSetVerifier = DefaultJWTClaimsVerifier<SecurityContext>(
            JWTClaimsSet.Builder().build(),
            setOf(RFC7519.ISSUER, SdJwtVcSpec.VCT),
        )

        JwtSignatureVerifier {
            runCatching {
                val signedJwt = SignedJWT.parse(it)
                typeVerifier.verify(signedJwt.header.type, null)
                claimSetVerifier.verify(signedJwt.jwtClaimsSet, null)
                signedJwt
            }.getOrNull()
        }
    }

    suspend operator fun invoke(unverified: SdJwt, nonce: Nonce): SdJwtVcValidationResult {
        val challenge = buildJsonObject {
            put(Claims.Audience, audience)
            put(Claims.Nonce, nonce.value)
        }

        return verifySdJwtVc(unverified, challenge)
            .fold(
                ifRight = { SdJwtVcValidationResult.Valid(it) },
                ifLeft = { sdJwtVcError ->
                    val sdJwtVcValidationError = sdJwtVcError.toSdJwtVcValidationError()
                    log.error("SD-JWT-VC validation failed: ${sdJwtVcValidationError.description}", sdJwtVcError)
                    val errors =
                        if (!sdJwtVcError.isSignatureVerificationFailure()) nonEmptyListOf(sdJwtVcValidationError)
                        else verifySdJwt(unverified, challenge)
                            .fold(
                                ifRight = { nonEmptyListOf(sdJwtVcValidationError) },
                                ifLeft = { sdJwtError ->
                                    val sdJwtValidationError = sdJwtError.toSdJwtVcValidationError()
                                    log.error("SD-JWT validation failed: ${sdJwtValidationError.description}", sdJwtError)
                                    nonEmptyListOf(sdJwtVcValidationError, sdJwtValidationError)
                                },
                            )
                    SdJwtVcValidationResult.Invalid(errors)
                },
            )
    }

    private suspend fun verifySdJwtVc(unverified: SdJwt, challenge: JsonObject): Either<Throwable, JsonObject> =
        Either.catch {
            val (presentation, _) = sdJwtVcVerifier.verify(unverified, challenge).getOrThrow()

            with(NimbusSdJwtOps) {
                presentation.recreateClaims(visitor = null)
            }
        }

    private suspend fun verifySdJwt(unverified: SdJwt, challenge: JsonObject): Either<Throwable, JsonObject> =
        Either.catch {
            val (presentation, _) = NimbusSdJwtOps.verify(
                jwtSignatureVerifier = sdJwtVcNoSignatureVerification,
                unverifiedSdJwt = unverified,
                keyBindingVerifier = KeyBindingVerifier.mustBePresentAndValid(HolderPubKeyInConfirmationClaim, challenge),
            ).getOrThrow()

            with(NimbusSdJwtOps) {
                presentation.recreateClaims(visitor = null)
            }
        }
}

private fun Throwable.isSignatureVerificationFailure(): Boolean =
    when (this) {
        is SdJwtVerificationException -> when (val reason = reason) {
            is VerificationError.InvalidJwt ->
                reason.cause is BadJOSEException && (reason.cause?.message?.startsWith("Signed JWT rejected") ?: false)
            is VerificationError.SdJwtVcError ->
                reason.error is IssuerKeyVerificationError
            else -> false
        }
        else -> false
    }

private fun Throwable.toSdJwtVcValidationError(): SdJwtVcValidationError {
    val (reason, description) = when (this) {
        is SdJwtVerificationException -> toSdJwtVcValidationErrorTO() to description
        else -> SdJwtVcValidationErrorTO.UnexpectedError to "an unexpected error occurred${message?.let { ": $it" } ?: ""}"
    }
    return SdJwtVcValidationError(reason, description, this)
}

private fun SdJwtVerificationException.toSdJwtVcValidationErrorTO(): SdJwtVcValidationErrorTO =
    when (val reason = this.reason) {
        VerificationError.ParsingError -> SdJwtVcValidationErrorTO.IsUnparsable
        is VerificationError.InvalidJwt -> SdJwtVcValidationErrorTO.ContainsInvalidJwt
        is VerificationError.KeyBindingFailed -> reason.details.toSdJwtVcValidationErrorTO()
        is VerificationError.InvalidDisclosures -> SdJwtVcValidationErrorTO.ContainsInvalidDisclosures
        is VerificationError.UnsupportedHashingAlgorithm -> SdJwtVcValidationErrorTO.ContainsUnsupportedHashingAlgorithm
        VerificationError.NonUniqueDisclosures -> SdJwtVcValidationErrorTO.ContainsNonUniqueDisclosures
        VerificationError.NonUniqueDisclosureDigests -> SdJwtVcValidationErrorTO.ContainsNonUniqueDigests
        is VerificationError.MissingDigests -> SdJwtVcValidationErrorTO.ContainsDisclosuresWithNoDigests
        is VerificationError.SdJwtVcError -> reason.error.toSdJwtVcValidationErrorTO()
    }

private fun KeyBindingError.toSdJwtVcValidationErrorTO(): SdJwtVcValidationErrorTO =
    when (this) {
        KeyBindingError.MissingHolderPubKey -> SdJwtVcValidationErrorTO.IsMissingHolderPublicKey
        KeyBindingError.InvalidKeyBindingJwt -> SdJwtVcValidationErrorTO.ContainsInvalidKeyBindingJwt
        KeyBindingError.UnexpectedKeyBindingJwt -> SdJwtVcValidationErrorTO.ContainsKeyBindingJwt
        KeyBindingError.MissingKeyBindingJwt -> SdJwtVcValidationErrorTO.IsMissingKeyBindingJwt
    }

private fun SdJwtVcVerificationError.toSdJwtVcValidationErrorTO(): SdJwtVcValidationErrorTO =
    when (this) {
        is IssuerKeyVerificationError.UnsupportedVerificationMethod -> SdJwtVcValidationErrorTO.UnsupportedVerificationMethod
        is IssuerKeyVerificationError.IssuerMetadataResolutionFailure -> SdJwtVcValidationErrorTO.UnableToResolveIssuerMetadata
        is IssuerKeyVerificationError.UntrustedIssuerCertificate -> SdJwtVcValidationErrorTO.IssuerCertificateIsNotTrusted
        is IssuerKeyVerificationError.DIDLookupFailure -> SdJwtVcValidationErrorTO.UnableToLookupDID
        IssuerKeyVerificationError.CannotDetermineIssuerVerificationMethod -> SdJwtVcValidationErrorTO.UnableToDetermineVerificationMethod
    }
