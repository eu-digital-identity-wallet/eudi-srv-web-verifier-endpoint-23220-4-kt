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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc

import arrow.core.*
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerificationError
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerificationError.IssuerKeyVerificationError
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerifier
import eu.europa.ec.eudi.sdjwt.vc.X509CertificateTrust
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.ProvideTrustSource
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.applyCatching
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierId
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.slf4j.LoggerFactory
import java.security.cert.X509Certificate
import eu.europa.ec.eudi.sdjwt.vc.KtorHttpClientFactory

internal enum class SdJwtVcValidationErrorCode {
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
}

internal data class SdJwtVcValidationError(val reason: SdJwtVcValidationErrorCode, val cause: Throwable) {
    companion object {
        operator fun invoke(cause: Throwable): SdJwtVcValidationError = SdJwtVcValidationError(cause.toSdJwtVcValidationErrorCode(), cause)
    }
}

private fun Throwable.toSdJwtVcValidationErrorCode(): SdJwtVcValidationErrorCode =
    when (this) {
        is SdJwtVerificationException -> toSdJwtVcValidationErrorCode()
        is StatusCheckException -> SdJwtVcValidationErrorCode.StatusCheckFailed
        else -> SdJwtVcValidationErrorCode.UnexpectedError
    }

private fun SdJwtVerificationException.toSdJwtVcValidationErrorCode(): SdJwtVcValidationErrorCode =
    when (val reason = this.reason) {
        VerificationError.ParsingError -> SdJwtVcValidationErrorCode.IsUnparsable
        is VerificationError.InvalidJwt -> SdJwtVcValidationErrorCode.ContainsInvalidJwt
        is VerificationError.KeyBindingFailed -> reason.details.toSdJwtVcValidationErrorCode()
        is VerificationError.InvalidDisclosures -> SdJwtVcValidationErrorCode.ContainsInvalidDisclosures
        is VerificationError.UnsupportedHashingAlgorithm -> SdJwtVcValidationErrorCode.ContainsUnsupportedHashingAlgorithm
        is VerificationError.NonUniqueDisclosures -> SdJwtVcValidationErrorCode.ContainsNonUniqueDisclosures
        VerificationError.NonUniqueDisclosureDigests -> SdJwtVcValidationErrorCode.ContainsNonUniqueDigests
        is VerificationError.MissingDigests -> SdJwtVcValidationErrorCode.ContainsDisclosuresWithNoDigests
        is VerificationError.SdJwtVcError -> reason.error.toSdJwtVcValidationErrorCode()
    }

private fun KeyBindingError.toSdJwtVcValidationErrorCode(): SdJwtVcValidationErrorCode =
    when (this) {
        KeyBindingError.MissingHolderPublicKey -> SdJwtVcValidationErrorCode.IsMissingHolderPublicKey
        KeyBindingError.UnsupportedHolderPublicKey -> SdJwtVcValidationErrorCode.UnsupportedHolderPublicKey
        is KeyBindingError.InvalidKeyBindingJwt -> SdJwtVcValidationErrorCode.ContainsInvalidKeyBindingJwt
        KeyBindingError.UnexpectedKeyBindingJwt -> SdJwtVcValidationErrorCode.ContainsKeyBindingJwt
        KeyBindingError.MissingKeyBindingJwt -> SdJwtVcValidationErrorCode.IsMissingKeyBindingJwt
    }

private fun SdJwtVcVerificationError.toSdJwtVcValidationErrorCode(): SdJwtVcValidationErrorCode =
    when (this) {
        is IssuerKeyVerificationError.UnsupportedVerificationMethod -> SdJwtVcValidationErrorCode.UnsupportedVerificationMethod
        is IssuerKeyVerificationError.IssuerMetadataResolutionFailure -> SdJwtVcValidationErrorCode.UnableToResolveIssuerMetadata
        is IssuerKeyVerificationError.UntrustedIssuerCertificate -> SdJwtVcValidationErrorCode.IssuerCertificateIsNotTrusted
        is IssuerKeyVerificationError.DIDLookupFailure -> SdJwtVcValidationErrorCode.UnableToLookupDID
        IssuerKeyVerificationError.CannotDetermineIssuerVerificationMethod -> SdJwtVcValidationErrorCode.UnableToDetermineVerificationMethod
    }

private val log = LoggerFactory.getLogger(SdJwtVcValidator::class.java)

internal class SdJwtVcValidator(
    provideTrustSource: ProvideTrustSource,
    private val audience: VerifierId,
    private val statusListTokenValidator: StatusListTokenValidator?,
    private val httpClientFactory: KtorHttpClientFactory,
) {
    private val sdJwtVcVerifier: SdJwtVcVerifier<SignedJWT> = run {
        val x509CertificateTrust = X509CertificateTrust.usingVct { chain: List<X509Certificate>, vct ->
            val x5CShouldBe = provideTrustSource(vct)
            if (x5CShouldBe != null) {
                val x5cValidator = X5CValidator(x5CShouldBe)
                val x5c = checkNotNull(chain.toNonEmptyListOrNull())
                x5cValidator.ensureTrusted(x5c).fold(ifLeft = { false }, ifRight = { true })
            } else {
                false
            }
        }
        NimbusSdJwtOps.SdJwtVcVerifier.usingX5cOrIssuerMetadata(x509CertificateTrust, httpClientFactory)
    }
    private val sdJwtVcVerifierNoSignatureVerification: SdJwtVcVerifier<SignedJWT> by lazy {
        val noSignatureVerifier = run {
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

        val keyBindingVerifierFactory: (JsonObject?) -> KeyBindingVerifier.MustBePresentAndValid<SignedJWT> =
            with(NimbusSdJwtOps) {
                {
                    KeyBindingVerifier.mustBePresentAndValid(HolderPubKeyInConfirmationClaim, it)
                }
            }

        object : SdJwtVcVerifier<SignedJWT> {
            override suspend fun verify(unverifiedSdJwt: String): Result<SdJwt<SignedJWT>> =
                NimbusSdJwtOps.verify(noSignatureVerifier, unverifiedSdJwt)

            override suspend fun verify(unverifiedSdJwt: JsonObject): Result<SdJwt<SignedJWT>> =
                NimbusSdJwtOps.verify(noSignatureVerifier, unverifiedSdJwt)

            override suspend fun verify(unverifiedSdJwt: String, challenge: JsonObject?): Result<SdJwtAndKbJwt<SignedJWT>> =
                NimbusSdJwtOps.verify(noSignatureVerifier, keyBindingVerifierFactory(challenge), unverifiedSdJwt)

            override suspend fun verify(unverifiedSdJwt: JsonObject, challenge: JsonObject?): Result<SdJwtAndKbJwt<SignedJWT>> =
                NimbusSdJwtOps.verify(noSignatureVerifier, keyBindingVerifierFactory(challenge), unverifiedSdJwt)
        }
    }

    suspend fun validate(
        unverified: String,
        nonce: Nonce,
        transactionId: TransactionId? = null,
    ): Either<NonEmptyList<SdJwtVcValidationError>, SdJwtAndKbJwt<SignedJWT>> =
        validate(unverified.right(), nonce, transactionId)

    suspend fun validate(
        unverified: JsonObject,
        nonce: Nonce,
        transactionId: TransactionId? = null,
    ): Either<NonEmptyList<SdJwtVcValidationError>, SdJwtAndKbJwt<SignedJWT>> =
        validate(unverified.left(), nonce, transactionId)

    private suspend fun validate(
        unverified: Either<JsonObject, String>,
        nonce: Nonce,
        transactionId: TransactionId?,
    ): Either<NonEmptyList<SdJwtVcValidationError>, SdJwtAndKbJwt<SignedJWT>> {
        val challenge = buildJsonObject {
            put(RFC7519.AUDIENCE, audience.clientId)
            put("nonce", nonce.value)
        }

        return Either.catch {
            sdJwtVcVerifier.verify(unverified, challenge, transactionId).getOrThrow()
        }.fold(
            ifRight = { it.right() },
            ifLeft = { sdJwtVcError ->
                log.error("SD-JWT-VC validation failed: ${sdJwtVcError.description}", sdJwtVcError)
                val errors =
                    if (!sdJwtVcError.isSignatureVerificationFailure()) nonEmptyListOf(SdJwtVcValidationError(sdJwtVcError))
                    else Either.catch {
                        sdJwtVcVerifierNoSignatureVerification.verify(unverified, challenge, transactionId).getOrThrow()
                    }.fold(
                        ifRight = { nonEmptyListOf(SdJwtVcValidationError(sdJwtVcError)) },
                        ifLeft = { sdJwtError ->
                            log.error("SD-JWT validation failed: ${sdJwtError.description}", sdJwtError)
                            nonEmptyListOf(SdJwtVcValidationError(sdJwtVcError), SdJwtVcValidationError(sdJwtError))
                        },
                    )
                errors.left()
            },
        )
    }

    private suspend fun SdJwtVcVerifier<SignedJWT>.verify(
        unverified: Either<JsonObject, String>,
        challenge: JsonObject,
        transactionId: TransactionId?,
    ): Result<SdJwtAndKbJwt<SignedJWT>> =
        unverified.fold(
            ifLeft = { verify(it, challenge) },
            ifRight = { verify(it, challenge) },
        ).applyCatching {
            statusListTokenValidator?.validate(this, transactionId)
        }
}

private val Throwable.description: String
    get() = when (this) {
        is SdJwtVerificationException -> description
        is StatusCheckException -> reason
        else -> message ?: "n/a"
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
