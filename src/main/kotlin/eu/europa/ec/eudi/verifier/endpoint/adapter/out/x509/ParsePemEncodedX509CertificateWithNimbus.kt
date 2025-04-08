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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509

import com.nimbusds.jose.util.X509CertUtils
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ParsePemEncodedX509Certificate
import java.security.cert.X509Certificate

/**
 * [ParsePemEncodedX509Certificate] implementation using Nimbus.
 */
internal object ParsePemEncodedX509CertificateWithNimbus : ParsePemEncodedX509Certificate {

    override fun invoke(pem: String): Result<X509Certificate> =
        runCatching {
            require(pem.isNotBlank()) { "pem cannot be blank" }
            X509CertUtils.parseWithException(pem)
        }
}
