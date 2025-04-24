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
package eu.europa.ec.eudi.verifier.endpoint.port.out.x509

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.ConfigurePKIXParameters
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.SkipRevocation
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import java.security.cert.X509Certificate

/**
 * Parses a PEM encoded X509 Certificate.
 */
fun interface ParsePemEncodedX509Certificate {
    operator fun invoke(pem: String): Result<X509Certificate>
    operator fun invoke(pems: NonEmptyList<String>): Result<NonEmptyList<X509Certificate>> =
        runCatching { pems.map { invoke(it).getOrThrow() } }
}

fun ParsePemEncodedX509Certificate.x5cShouldBeTrustedOrNull(
    rootCACertificates: List<String>?,
    customizePKIX: ConfigurePKIXParameters = SkipRevocation,
): Result<X5CShouldBe.Trusted?> = runCatching {
    rootCACertificates?.toNonEmptyListOrNull()?.let { certsInPem ->
        val certs = invoke(certsInPem).getOrThrow()
        X5CShouldBe.Trusted(certs, customizePKIX)
    }
}
