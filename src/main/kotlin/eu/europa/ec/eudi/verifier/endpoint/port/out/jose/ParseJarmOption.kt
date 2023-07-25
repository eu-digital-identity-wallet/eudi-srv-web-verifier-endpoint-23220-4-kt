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
package eu.europa.ec.eudi.verifier.endpoint.port.out.jose

import eu.europa.ec.eudi.verifier.endpoint.domain.JarmOption

/**
 * Models a function that parses three strings into a [JarmOption]
 */
interface ParseJarmOption {

    /**
     *
     * @param jwsAlg an optional string representing a JWS algorithm
     * @param jweAlg an optional string representing a JWE algorithm
     * @param encryptionMethod an optional string representing an encryption method
     * @return a [JarmOption] or null
     */
    operator fun invoke(jwsAlg: String?, jweAlg: String?, encryptionMethod: String?): JarmOption? {
        val signed: JarmOption.Signed? =
            if (!jwsAlg.isNullOrBlank()) JarmOption.Signed(jwsAlgOf(jwsAlg)) else null
        val encrypted: JarmOption.Encrypted? =
            if (!jweAlg.isNullOrBlank() && !encryptionMethod.isNullOrBlank()) {
                JarmOption.Encrypted(jweAlgOf(jweAlg), encMethodOf(encryptionMethod))
            } else null

        return when {
            signed != null && encrypted != null -> JarmOption.SignedAndEncrypted(signed, encrypted)
            signed != null && encrypted == null -> signed
            signed == null && encrypted != null -> encrypted
            else -> null
        }
    }

    fun jwsAlgOf(s: String): String
    fun jweAlgOf(s: String): String
    fun encMethodOf(s: String): String
}
