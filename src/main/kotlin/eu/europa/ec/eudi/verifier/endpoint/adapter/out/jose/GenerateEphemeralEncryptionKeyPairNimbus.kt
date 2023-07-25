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

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.verifier.endpoint.domain.EphemeralEncryptionKeyPairJWK
import eu.europa.ec.eudi.verifier.endpoint.domain.JarmOption
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.GenerateEphemeralEncryptionKeyPair
import java.util.*

/**
 * An implementation of [GenerateEphemeralEncryptionKeyPair] that uses Nimbus SDK
 */
object GenerateEphemeralEncryptionKeyPairNimbus : GenerateEphemeralEncryptionKeyPair {

    override fun invoke(
        encryptedResponse: JarmOption.Encrypted,
    ): Result<EphemeralEncryptionKeyPairJWK> {
        val alg = encryptedResponse.nimbusAlg()
        return createEphemeralEncryptionKey(alg).map { EphemeralEncryptionKeyPairJWK.from(keyPair = it) }
    }

    private fun createEphemeralEncryptionKey(alg: JWEAlgorithm): Result<ECKey> = runCatching {
        val ecKeyGenerator = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(alg)
            .keyID(UUID.randomUUID().toString())
        ecKeyGenerator.generate()
    }
}

fun EphemeralEncryptionKeyPairJWK.Companion.from(keyPair: ECKey): EphemeralEncryptionKeyPairJWK {
    return EphemeralEncryptionKeyPairJWK(keyPair.toJSONString())
}

fun EphemeralEncryptionKeyPairJWK.jwk(): JWK = JWK.parse(value)
