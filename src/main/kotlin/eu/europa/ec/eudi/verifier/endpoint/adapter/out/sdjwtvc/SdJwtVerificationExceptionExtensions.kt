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

internal val SdJwtVerificationException.description: String
    get() = when (val reason = reason) {
        is VerificationError.InvalidDisclosures -> "sd-jwt vc contains invalid disclosures"
        VerificationError.InvalidJwt -> "sd-jwt vc contains an invalid jwt"
        is VerificationError.KeyBindingFailed -> when (reason.details) {
            KeyBindingError.InvalidKeyBindingJwt -> "keybinding jwt is not valid"
            KeyBindingError.MissingHolderPubKey -> "missing holder public key (cnf)"
            KeyBindingError.MissingKeyBindingJwt -> "missing keybinding jwt"
            KeyBindingError.UnexpectedKeyBindingJwt -> "keybinding jwt was not expected"
        }
        is VerificationError.MissingDigests -> "sd-jwt vc contains disclosures for non-existing digests"
        VerificationError.MissingOrUnknownHashingAlgorithm -> "sd-jwt vc contains an unknown or unsupported hash algorithm"
        VerificationError.NonUniqueDisclosureDigests -> "sd-jwt vc contains non-unique digests"
        VerificationError.NonUniqueDisclosures -> "sd-jwt vc contains non-unique disclosures"
        is VerificationError.Other -> reason.value
        VerificationError.ParsingError -> "sd-jwt vc could not be parsed"
    }
