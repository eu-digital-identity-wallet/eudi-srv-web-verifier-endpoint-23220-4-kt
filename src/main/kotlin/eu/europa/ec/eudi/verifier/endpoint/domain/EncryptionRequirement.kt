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
package eu.europa.ec.eudi.verifier.endpoint.domain

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.*

sealed interface EncryptionRequirement {

    data object NotRequired : EncryptionRequirement

    data class Required(
        val jwk: JWK,
        val algorithm: JWEAlgorithm,
        val method: EncryptionMethod,
    ) : EncryptionRequirement {
        init {
            require(jwk.isSupportedEncryptionJwk()) { "unsupported jwk" }
            require(!jwk.isPrivate) { "jwk must not be private" }
            require(algorithm in jwk.supportedEncryptionAlgorithms) { "unsupported encryption algorithm" }
            require(method in jwk.supportedEncryptionMethods) { "unsupported encryption method" }
        }

        companion object
    }
}

internal fun JWK.isSupportedEncryptionJwk(): Boolean =
    if (null == keyUse || KeyUse.ENCRYPTION == keyUse) {
        when (this) {
            is RSAKey -> true
            is ECKey -> Curve.P_256 == curve || Curve.P_384 == curve || Curve.P_521 == curve
            is OctetKeyPair -> Curve.X25519 == curve
            else -> false
        }
    } else false

internal val JWK.supportedEncryptionAlgorithms: NonEmptyList<JWEAlgorithm>
    get() = when (this) {
        is RSAKey -> supportedEncryptionAlgorithms
        is ECKey -> supportedEncryptionAlgorithms
        is OctetKeyPair -> supportedEncryptionAlgorithms
        else -> error("Unsupported JWK type '${this::class.qualifiedName}'")
    }

internal val JWK.supportedEncryptionMethods: NonEmptyList<EncryptionMethod>
    get() = nonEmptyListOf(
        EncryptionMethod.A128CBC_HS256,
        EncryptionMethod.A192CBC_HS384,
        EncryptionMethod.A256CBC_HS512,
        EncryptionMethod.A128GCM,
        EncryptionMethod.A192GCM,
        EncryptionMethod.A256GCM,
        EncryptionMethod.XC20P,
    )

internal val RSAKey.supportedEncryptionAlgorithms: NonEmptyList<JWEAlgorithm>
    get() = nonEmptyListOf(
        JWEAlgorithm.RSA_OAEP_256,
        JWEAlgorithm.RSA_OAEP_384,
        JWEAlgorithm.RSA_OAEP_512,
    )

internal val ECKey.supportedEncryptionAlgorithms: NonEmptyList<JWEAlgorithm>
    get() = nonEmptyListOf(
        JWEAlgorithm.ECDH_ES,
        JWEAlgorithm.ECDH_ES_A128KW,
        JWEAlgorithm.ECDH_ES_A128KW,
        JWEAlgorithm.ECDH_ES_A256KW,
    )

internal val OctetKeyPair.supportedEncryptionAlgorithms: NonEmptyList<JWEAlgorithm>
    get() = nonEmptyListOf(
        JWEAlgorithm.ECDH_ES,
        JWEAlgorithm.ECDH_ES_A128KW,
        JWEAlgorithm.ECDH_ES_A128KW,
        JWEAlgorithm.ECDH_ES_A256KW,
    )
