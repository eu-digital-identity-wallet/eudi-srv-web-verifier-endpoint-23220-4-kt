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

import eu.europa.ec.eudi.verifier.endpoint.domain.EncryptionRequirement
import eu.europa.ec.eudi.verifier.endpoint.domain.Jwt
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import java.time.Clock

/**
 * An out port that signs and encrypts a [Presentation.Requested]
 */
fun interface CreateJar {
    operator fun invoke(
        verifierConfig: VerifierConfig,
        clock: Clock,
        presentation: Presentation.Requested,
        walletNonce: String?,
        walletJarEncryptionRequirement: EncryptionRequirement,
    ): Result<Jwt>
}
