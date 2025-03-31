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

import eu.europa.ec.eudi.sdjwt.KeyBindingError
import eu.europa.ec.eudi.sdjwt.SdJwtVerificationException
import eu.europa.ec.eudi.sdjwt.VerificationError
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerificationError

internal val SdJwtVerificationException.description: String
    get() {
        fun joinNotBlank(vararg values: String?): String = values.filterNot { it.isNullOrBlank() }.joinToString(", ")

        fun descriptionOf(sdJwtError: VerificationError): String {
            fun descriptionOf(error: Throwable?): String? =
                when (error) {
                    is SdJwtVerificationException -> descriptionOf(error.reason)
                    else -> error?.message
                }

            return when (sdJwtError) {
                VerificationError.ParsingError -> "sd-jwt could not be parsed"
                is VerificationError.InvalidJwt ->
                    joinNotBlank("sd-jwt contains an invalid jwt", sdJwtError.message, descriptionOf(sdJwtError.cause))
                is VerificationError.KeyBindingFailed -> when (val details = sdJwtError.details) {
                    KeyBindingError.MissingHolderPublicKey -> "missing holder public key (cnf)"
                    KeyBindingError.UnsupportedHolderPublicKey -> "unsupported holder public key (cnf) type"
                    is KeyBindingError.InvalidKeyBindingJwt ->
                        joinNotBlank("keybinding jwt is not valid", details.message, descriptionOf(details.cause))
                    KeyBindingError.UnexpectedKeyBindingJwt -> "keybinding jwt was not expected"
                    KeyBindingError.MissingKeyBindingJwt -> "missing keybinding jwt"
                }
                is VerificationError.InvalidDisclosures -> "sd-jwt contains invalid disclosures"
                is VerificationError.UnsupportedHashingAlgorithm -> "sd-jwt contains an unsupported hash algorithm: ${sdJwtError.algorithm}"
                VerificationError.NonUniqueDisclosures -> "sd-jwt contains non-unique disclosures"
                VerificationError.NonUniqueDisclosureDigests -> "sd-jwt contains non-unique digests"
                is VerificationError.MissingDigests -> "sd-jwt contains disclosures for non-existing digests"
                is VerificationError.SdJwtVcError -> when (val sdJwtVcError = sdJwtError.error) {
                    is SdJwtVcVerificationError.IssuerKeyVerificationError.UnsupportedVerificationMethod ->
                        "sd-jwt vc requires ${sdJwtVcError.method}, but this verification method is not enabled"
                    is SdJwtVcVerificationError.IssuerKeyVerificationError.IssuerMetadataResolutionFailure ->
                        joinNotBlank("unable to resolve sd-jwt vc issuer metadata", descriptionOf(sdJwtVcError.cause))
                    is SdJwtVcVerificationError.IssuerKeyVerificationError.UntrustedIssuerCertificate ->
                        joinNotBlank("sd-jwt vc issuer certificate is not trusted", sdJwtVcError.reason)
                    is SdJwtVcVerificationError.IssuerKeyVerificationError.DIDLookupFailure ->
                        joinNotBlank("did lookup failed", sdJwtVcError.message, descriptionOf(sdJwtVcError.cause))
                    SdJwtVcVerificationError.IssuerKeyVerificationError.CannotDetermineIssuerVerificationMethod ->
                        "cannot determine verification method for sd-jwt vc. missing 'x5c' header claim, issuer is not an https url or did"
                }
            }
        }

        return descriptionOf(reason)
    }
