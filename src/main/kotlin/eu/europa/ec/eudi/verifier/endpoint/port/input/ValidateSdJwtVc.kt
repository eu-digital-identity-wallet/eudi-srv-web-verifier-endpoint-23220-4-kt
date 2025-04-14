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
import eu.europa.ec.eudi.sdjwt.vc.KtorHttpClientFactory
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerificationError
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerificationError.IssuerKeyVerificationError
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerifier
import eu.europa.ec.eudi.statium.*
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.toJsonObject
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.description
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.datetime.toKotlinInstant
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory

/**
 * Reasons why validation of an SD-JWT Verifiable Credential might fail.
 */
@Serializable
enum class SdJwtVcValidationErrorTO {
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

data class SdJwtVcValidationError(
    val reason: SdJwtVcValidationErrorTO,
    val description: String,
    val cause: Throwable?,
)

data class StatusCheckException(val reason: String, val causedBy: Throwable) : Exception(reason, causedBy)

sealed interface SdJwtVcValidationResult {
    /**
     * Successfully validated an SD-JWT Verifiable Credential.
     */
    data class Valid(val payload: SdJwtAndKbJwt<SignedJWT>) : SdJwtVcValidationResult

    /**
     * SD-JWT Verifiable Credential validation failed.
     */
    data class Invalid(val errors: NonEmptyList<SdJwtVcValidationError>) : SdJwtVcValidationResult
}

fun SdJwtVcValidationResult.Invalid.toJson(): JsonArray = buildJsonArray {
    errors.forEach { error ->
        addJsonObject {
            put("error", error.reason.name)
            put("description", error.description)
            error.cause?.message?.let { cause -> put("cause", cause) }
        }
    }
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
    private val publishPresentationEvent: PublishPresentationEvent,
    private val sdJwtVcVerifier: SdJwtVcVerifier<SignedJWT>,
    private val audience: Audience,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
    private val clock: java.time.Clock,
    private val shouldCheckStatus: Boolean,
) {

    private sealed interface SdJwtSerialization {
        data class Compact(val value: SdJwt) : SdJwtSerialization
        data class Flattened(val value: JsonObject) : SdJwtSerialization
    }

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

    suspend operator fun invoke(unverified: JsonObject, nonce: Nonce, transactionId: TransactionId? = null): SdJwtVcValidationResult =
        doInvoke(
            unverified = SdJwtSerialization.Flattened(unverified),
            nonce = nonce,
            transactionId = transactionId,
        )

    suspend operator fun invoke(unverified: SdJwt, nonce: Nonce, transactionId: TransactionId? = null): SdJwtVcValidationResult =
        doInvoke(
            unverified = SdJwtSerialization.Compact(unverified),
            nonce = nonce,
            transactionId = transactionId,
        )

    private suspend fun doInvoke(
        unverified: SdJwtSerialization,
        nonce: Nonce,
        transactionId: TransactionId? = null,
    ): SdJwtVcValidationResult {
        val challenge = buildJsonObject {
            put(Claims.Audience, audience)
            put(Claims.Nonce, nonce.value)
        }

        return verifySdJwtVc(unverified, challenge, transactionId)
            .fold(
                ifRight = { SdJwtVcValidationResult.Valid(it) },
                ifLeft = { sdJwtVcError ->
                    val sdJwtVcValidationError = sdJwtVcError.toSdJwtVcValidationError()
                    log.error("SD-JWT-VC validation failed: ${sdJwtVcValidationError.description}", sdJwtVcError)
                    val errors =
                        if (!sdJwtVcError.isSignatureVerificationFailure()) nonEmptyListOf(sdJwtVcValidationError)
                        else verifySdJwtVcNoSig(unverified, challenge, transactionId)
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

    private suspend fun verifySdJwtVc(
        unverified: SdJwtSerialization,
        challenge: JsonObject,
        transactionId: TransactionId?,
    ): Either<Throwable, SdJwtAndKbJwt<SignedJWT>> = Either.catch {
        val sdJwtAndKbJwt = when (unverified) {
            is SdJwtSerialization.Compact -> sdJwtVcVerifier.verify(unverified.value, challenge).getOrThrow()
            is SdJwtSerialization.Flattened -> sdJwtVcVerifier.verify(unverified.value, challenge).getOrThrow()
        }
        if (shouldCheckStatus) {
            sdJwtAndKbJwt.sdJwt.jwt.verifyStatus(transactionId)
        }

        sdJwtAndKbJwt
    }

    private suspend fun verifySdJwtVcNoSig(
        unverified: SdJwtSerialization,
        challenge: JsonObject,
        transactionId: TransactionId?,
    ): Either<Throwable, SdJwtAndKbJwt<SignedJWT>> = Either.catch {
        val keyBindingVerifier = KeyBindingVerifier.mustBePresentAndValid(HolderPubKeyInConfirmationClaim, challenge)
        val sdJwtAndKbJwt = when (unverified) {
            is SdJwtSerialization.Compact -> NimbusSdJwtOps.verify(
                sdJwtVcNoSignatureVerification,
                keyBindingVerifier,
                unverified.value,
            ).getOrThrow()

            is SdJwtSerialization.Flattened -> NimbusSdJwtOps.verify(
                sdJwtVcNoSignatureVerification,
                keyBindingVerifier,
                unverified.value,
            ).getOrThrow()
        }
        if (shouldCheckStatus) {
            sdJwtAndKbJwt.sdJwt.jwt.verifyStatus(transactionId)
        }

        sdJwtAndKbJwt
    }

    private suspend fun SignedJWT.verifyStatus(transactionId: TransactionId?) {
        statusReference()?.let { statusReference ->
            runCatching {
                with(getStatus()) {
                    statusReference.currentStatus().getOrThrow()
                }.also {
                    require(it == Status.Valid) { "Attestation status expected to be VALID but is $it" }
                }
            }.fold(
                onSuccess = {
                    transactionId?.let { logStatusCheckSuccess(transactionId, statusReference) }
                },
                onFailure = { error ->
                    transactionId?.let { logStatusCheckFailed(transactionId, statusReference, error) }
                    throw StatusCheckException("Attestation status check failed, ${error.message}", error)
                },
            )
        }
    }

    private fun SignedJWT.statusReference(): StatusReference? {
        val statusElement = jwtClaimsSet.getJSONObjectClaim(TokenStatusListSpec.STATUS) ?: return null
        val statusJsonObject = statusElement.toJsonObject()
        val statusListElement = statusJsonObject[TokenStatusListSpec.STATUS_LIST]
        requireNotNull(statusListElement) {
            "Expected status_list element but not found"
        }
        require(statusListElement is JsonObject) {
            "Malformed status_list element"
        }

        val index = StatusIndex(statusListElement[TokenStatusListSpec.IDX]?.decodeAs<Int>()?.getOrThrow()!!)
        val uri = statusListElement[TokenStatusListSpec.URI]?.decodeAs<String>()?.getOrThrow()!!

        return StatusReference(index, uri)
    }

    private fun getStatus(): GetStatus {
        val delegateClock = object : Clock {
            override fun now(): Instant = clock.instant().toKotlinInstant()
        }
        val getStatusListToken: GetStatusListToken = GetStatusListToken.usingJwt(
            clock = delegateClock,
            httpClientFactory = ktorHttpClientFactory,
            verifyStatusListTokenSignature = VerifyStatusListTokenSignature.Ignore, // TODO: control it via configuration
        )
        return GetStatus(getStatusListToken)
    }

    private suspend fun logStatusCheckSuccess(transactionId: TransactionId, statusReference: StatusReference) {
        val event = PresentationEvent.AttestationStatusCheckSuccessful(transactionId, clock.instant(), statusReference)
        publishPresentationEvent(event)
    }

    private suspend fun logStatusCheckFailed(transactionId: TransactionId, statusReference: StatusReference, error: Throwable) {
        val event = PresentationEvent.AttestationStatusCheckFailed(transactionId, clock.instant(), statusReference, error.message)
        publishPresentationEvent(event)
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
        is StatusCheckException -> SdJwtVcValidationErrorTO.StatusCheckFailed to reason
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
        KeyBindingError.MissingHolderPublicKey -> SdJwtVcValidationErrorTO.IsMissingHolderPublicKey
        KeyBindingError.UnsupportedHolderPublicKey -> SdJwtVcValidationErrorTO.UnsupportedHolderPublicKey
        is KeyBindingError.InvalidKeyBindingJwt -> SdJwtVcValidationErrorTO.ContainsInvalidKeyBindingJwt
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
