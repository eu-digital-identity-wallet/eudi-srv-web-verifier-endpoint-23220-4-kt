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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.verifier.endpoint.domain.JarmOption
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.ParseJarmOption

object ParseJarmOptionNimbus : ParseJarmOption {

    override operator fun invoke(jwsAlg: String?, jweAlg: String?, encryptionMethod: String?): JarmOption? {
        val signed = if (!jwsAlg.isNullOrBlank()) jwsAlg.signed() else null
        val encrypted = bothNotNull(jweAlg, encryptionMethod)?.encrypted()

        return when {
            signed != null && encrypted != null -> JarmOption.SignedAndEncrypted(signed, encrypted)
            signed != null && encrypted == null -> signed
            signed == null && encrypted != null -> encrypted
            else -> null
        }
    }

    private fun String.signed(): JarmOption.Signed =
        JarmOption.Signed(JWSAlgorithm.parse(this).name)

    private fun Pair<String, String>.encrypted(): JarmOption.Encrypted =
        JarmOption.Encrypted(
            JWEAlgorithm.parse(first).name,
            EncryptionMethod.parse(second).name,
        )

    private fun bothNotNull(a: String?, b: String?): Pair<String, String>? =
        if (!a.isNullOrBlank() && !b.isNullOrBlank()) a to b
        else null
}

internal fun JarmOption.Signed.nimbusAlg(): JWSAlgorithm = JWSAlgorithm.parse(algorithm)
internal fun JarmOption.Encrypted.nimbusAlg(): JWEAlgorithm = JWEAlgorithm.parse(algorithm)
internal fun JarmOption.Encrypted.nimbusEnc(): EncryptionMethod = EncryptionMethod.parse(encryptionMethod)
