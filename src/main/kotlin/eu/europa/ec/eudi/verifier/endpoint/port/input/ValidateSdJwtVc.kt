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
import arrow.core.getOrElse
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerifier
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
    ContainsInvalidDisclosures,
    ContainsInvalidJwt,
    ContainsInvalidKeyBindingJwt,
    IsMissingHolderPublicKey,
    IsMissingKeyBindingJwt,
    ContainsDisclosuresWithNoDigests,
    ContainsUnknownHashingAlgorithm,
    ContainsNonUniqueDigests,
    ContainsNonUniqueDisclosures,
    IsUnparsable,
    Other,
}

sealed interface SdJwtVcValidationResult {
    /**
     * Successfully validated an SD-JWT Verifiable Credential.
     */
    data class Valid(val payload: JsonObject) : SdJwtVcValidationResult

    /**
     * SD-JWT Verifiable Credential validation failed.
     */
    data class Invalid(val reason: SdJwtVcValidationErrorTO) : SdJwtVcValidationResult
}

internal typealias SdJwt = String
internal typealias Audience = String

private object Claims {
    val Audience = RFC7519.AUDIENCE
    val Nonce = "nonce"
}

/**
 * Validates an SD-JWT Verifiable Credential.
 *
 * @param verifier SdJwtVcVerifier used for verification
 * @param audience the Client Id of this Verifier, expected to be found in the KeyBinding JWT
 */
internal class ValidateSdJwtVc(
    private val verifier: SdJwtVcVerifier<SignedJWT>,
    private val audience: Audience,
) {
    suspend operator fun invoke(unverified: SdJwt, nonce: Nonce): SdJwtVcValidationResult {
        val challenge = buildJsonObject {
            put(Claims.Audience, audience)
            put(Claims.Nonce, nonce.value)
        }

        return Either.catch {
            val (presentation, _) = verifier.verify(unverified, challenge).getOrThrow()
            val payload = with(NimbusSdJwtOps) {
                presentation.recreateClaims(visitor = null)
            }
            SdJwtVcValidationResult.Valid(payload)
        }.getOrElse {
            log.error("SD-JWT-VC validation failed", it)
            if (it is SdJwtVerificationException) {
                SdJwtVcValidationResult.Invalid(it.toSdJwtVcValidationErrorTO())
            } else {
                SdJwtVcValidationResult.Invalid(SdJwtVcValidationErrorTO.Other)
            }
        }
    }
}

private val log = LoggerFactory.getLogger(ValidateSdJwtVc::class.java)

private fun SdJwtVerificationException.toSdJwtVcValidationErrorTO(): SdJwtVcValidationErrorTO =
    when (val reason = this.reason) {
        is VerificationError.InvalidDisclosures -> SdJwtVcValidationErrorTO.ContainsInvalidDisclosures
        VerificationError.InvalidJwt -> SdJwtVcValidationErrorTO.ContainsInvalidJwt
        is VerificationError.KeyBindingFailed -> reason.details.toSdJwtVcValidationErrorTO()
        is VerificationError.MissingDigests -> SdJwtVcValidationErrorTO.ContainsDisclosuresWithNoDigests
        VerificationError.MissingOrUnknownHashingAlgorithm -> SdJwtVcValidationErrorTO.ContainsUnknownHashingAlgorithm
        VerificationError.NonUniqueDisclosureDigests -> SdJwtVcValidationErrorTO.ContainsNonUniqueDigests
        VerificationError.NonUniqueDisclosures -> SdJwtVcValidationErrorTO.ContainsNonUniqueDisclosures
        is VerificationError.Other -> SdJwtVcValidationErrorTO.Other
        VerificationError.ParsingError -> SdJwtVcValidationErrorTO.IsUnparsable
    }

private fun KeyBindingError.toSdJwtVcValidationErrorTO(): SdJwtVcValidationErrorTO =
    when (this) {
        KeyBindingError.InvalidKeyBindingJwt -> SdJwtVcValidationErrorTO.ContainsInvalidKeyBindingJwt
        KeyBindingError.MissingHolderPubKey -> SdJwtVcValidationErrorTO.IsMissingHolderPublicKey
        KeyBindingError.MissingKeyBindingJwt -> SdJwtVcValidationErrorTO.IsMissingKeyBindingJwt
        KeyBindingError.UnexpectedKeyBindingJwt -> error("KeyBindingJwt is required, but verification failed with '$this'")
    }
