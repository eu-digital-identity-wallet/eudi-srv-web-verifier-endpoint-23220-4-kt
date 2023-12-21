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

internal fun String.nimbusJWSAlgorithm(): JWSAlgorithm {
    val alg = JWSAlgorithm.parse(this)
    require(alg in JWSAlgorithm.Family.SIGNATURE) { "$this is not a signing algorithm" }
    return alg
}

internal fun String.nimbusJWEAlgorithm(): JWEAlgorithm = when (this) {
    JWEAlgorithm.RSA_OAEP_256.name -> JWEAlgorithm.RSA_OAEP_256
    JWEAlgorithm.RSA_OAEP_384.name -> JWEAlgorithm.RSA_OAEP_384
    JWEAlgorithm.RSA_OAEP_512.name -> JWEAlgorithm.RSA_OAEP_512
    JWEAlgorithm.A128KW.name -> JWEAlgorithm.A128KW
    JWEAlgorithm.A192KW.name -> JWEAlgorithm.A192KW
    JWEAlgorithm.A256KW.name -> JWEAlgorithm.A256KW
    JWEAlgorithm.DIR.name -> JWEAlgorithm.DIR
    JWEAlgorithm.ECDH_ES.name -> JWEAlgorithm.ECDH_ES
    JWEAlgorithm.ECDH_ES_A128KW.name -> JWEAlgorithm.ECDH_ES_A128KW
    JWEAlgorithm.ECDH_ES_A192KW.name -> JWEAlgorithm.ECDH_ES_A192KW
    JWEAlgorithm.ECDH_ES_A256KW.name -> JWEAlgorithm.ECDH_ES_A256KW
    JWEAlgorithm.ECDH_1PU.name -> JWEAlgorithm.ECDH_1PU
    JWEAlgorithm.ECDH_1PU_A128KW.name -> JWEAlgorithm.ECDH_1PU_A128KW
    JWEAlgorithm.ECDH_1PU_A192KW.name -> JWEAlgorithm.ECDH_1PU_A192KW
    JWEAlgorithm.ECDH_1PU_A256KW.name -> JWEAlgorithm.ECDH_1PU_A256KW
    JWEAlgorithm.A128GCMKW.name -> JWEAlgorithm.A128GCMKW
    JWEAlgorithm.A192GCMKW.name -> JWEAlgorithm.A192GCMKW
    JWEAlgorithm.A256GCMKW.name -> JWEAlgorithm.A256GCMKW
    JWEAlgorithm.PBES2_HS256_A128KW.name -> JWEAlgorithm.PBES2_HS256_A128KW
    JWEAlgorithm.PBES2_HS384_A192KW.name -> JWEAlgorithm.PBES2_HS384_A192KW
    JWEAlgorithm.PBES2_HS512_A256KW.name -> JWEAlgorithm.PBES2_HS512_A256KW
    else -> error("$this is not a supported encryption algorithm")
}

internal fun String.nimbusEncryptionMethod(): EncryptionMethod = when (this) {
    EncryptionMethod.A128CBC_HS256.name -> EncryptionMethod.A128CBC_HS256
    EncryptionMethod.A192CBC_HS384.name -> EncryptionMethod.A192CBC_HS384
    EncryptionMethod.A256CBC_HS512.name -> EncryptionMethod.A256CBC_HS512
    EncryptionMethod.A128GCM.name -> EncryptionMethod.A128GCM
    EncryptionMethod.A192GCM.name -> EncryptionMethod.A192GCM
    EncryptionMethod.A256GCM.name -> EncryptionMethod.A256GCM
    EncryptionMethod.XC20P.name -> EncryptionMethod.XC20P
    else -> error("$this is not a supported encryption method")
}

internal fun JarmOption.Signed.nimbusJWSAlgorithm(): JWSAlgorithm = algorithm.nimbusJWSAlgorithm()
internal fun JarmOption.Encrypted.nimbusJWSAlgorithm(): JWEAlgorithm = algorithm.nimbusJWEAlgorithm()
internal fun JarmOption.Encrypted.nimbusEnc(): EncryptionMethod = encode.nimbusEncryptionMethod()
