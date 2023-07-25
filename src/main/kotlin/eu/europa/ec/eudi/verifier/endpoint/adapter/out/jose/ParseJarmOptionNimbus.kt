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
    override fun jwsAlgOf(s: String): String = s.nimbusJWSAlgorithm().name
    override fun jweAlgOf(s: String): String = s.nimbusJWEAlgorithm().name
    override fun encMethodOf(s: String): String = s.nimbusEncryptionMethod().name
}

internal fun String.nimbusJWSAlgorithm(): JWSAlgorithm = JWSAlgorithm.parse(this)
internal fun String.nimbusJWEAlgorithm(): JWEAlgorithm = JWEAlgorithm.parse(this)
internal fun String.nimbusEncryptionMethod(): EncryptionMethod = EncryptionMethod.parse(this)
internal fun JarmOption.Signed.nimbusJWSAlgorithm(): JWSAlgorithm = algorithm.nimbusJWSAlgorithm()
internal fun JarmOption.Encrypted.nimbusJWSAlgorithm(): JWEAlgorithm = algorithm.nimbusJWEAlgorithm()
internal fun JarmOption.Encrypted.nimbusEnc(): EncryptionMethod = encode.nimbusEncryptionMethod()
