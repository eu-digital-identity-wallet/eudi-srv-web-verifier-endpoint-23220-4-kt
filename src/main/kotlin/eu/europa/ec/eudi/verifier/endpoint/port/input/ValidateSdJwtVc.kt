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

import arrow.core.NonEmptyList
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import eu.europa.ec.eudi.sdjwt.SdJwtVerificationException
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.SdJwtVcValidationError
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.SdJwtVcValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.StatusCheckException
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.description
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import kotlinx.serialization.json.*

data class SdJwtVcValidationErrorDetailsTO(val reason: String, val description: String, val cause: Throwable?)

fun SdJwtVcValidationResult.Invalid.toJson(): JsonArray = buildJsonArray {
    errors.forEach { error ->
        addJsonObject {
            put("error", error.reason)
            put("description", error.description)
            error.cause?.message?.let { cause -> put("cause", cause) }
        }
    }
}

sealed interface SdJwtVcValidationResult {
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
    private val sdJwtVcValidator: SdJwtVcValidator,
) {

    suspend operator fun invoke(unverified: JsonObject, nonce: Nonce): SdJwtVcValidationResult =
        sdJwtVcValidator.validate(unverified, nonce, null)
            .fold(
                ifRight = { SdJwtVcValidationResult.Valid(it) },
                ifLeft = { errors -> SdJwtVcValidationResult.Invalid(errors.map { it.toSdJwtVcValidationError() }) },
            )

    suspend operator fun invoke(unverified: String, nonce: Nonce): SdJwtVcValidationResult =
        sdJwtVcValidator.validate(unverified, nonce, null)
            .fold(
                ifRight = { SdJwtVcValidationResult.Valid(it) },
                ifLeft = { errors -> SdJwtVcValidationResult.Invalid(errors.map { it.toSdJwtVcValidationError() }) },
            )
}

private fun SdJwtVcValidationError.toSdJwtVcValidationError(): SdJwtVcValidationErrorDetailsTO =
    SdJwtVcValidationErrorDetailsTO(
        reason = reason.name,
        description = when (cause) {
            is SdJwtVerificationException -> cause.description
            is StatusCheckException -> cause.reason
            else -> "an unexpected error occurred${cause.message?.let { ": $it" } ?: ""}"
        },
        cause = cause.cause,
    )
