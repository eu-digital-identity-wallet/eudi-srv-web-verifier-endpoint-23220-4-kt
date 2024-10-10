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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert

import arrow.core.Nel
import arrow.core.NonEmptyList
import java.security.KeyStore
import java.security.cert.*

typealias ConfigurePKIXParameters = PKIXParameters.() -> Unit


object CertValidationOps {
    private const val PKIX = "PKIX"
    private const val X509 = "X.509"

    private val SkipRevocation: ConfigurePKIXParameters = { isRevocationEnabled = false }

    @Throws(CertPathValidatorException::class)
    fun validateChain(
        chain: NonEmptyList<X509Certificate>,
        keyStore: KeyStore,
        customize: ConfigurePKIXParameters = SkipRevocation,
    ) {
        val param = run {
            PKIXParameters(keyStore).apply(customize)
        }
        validateChain(chain, param)
    }

    @Throws(CertPathValidatorException::class)
    fun validateChain(
        chain: Nel<X509Certificate>,
        trustedCerts: Nel<X509Certificate>,
        customize: ConfigurePKIXParameters = SkipRevocation,
    ) {
        val param = run {
            val trust = trustedCerts.map { TrustAnchor(it, null) }.toSet()
            PKIXParameters(trust).apply(customize)
        }
        validateChain(chain, param)
    }

    @Throws(CertPathValidatorException::class)
    fun validateChain(
        chain: NonEmptyList<X509Certificate>,
        pkixParameters: PKIXParameters,
    ) {
        val certPath = certPath(chain)
        val validator = certPathValidator()
        validator.validate(certPath, pkixParameters)
    }

    private fun certPath(chain: NonEmptyList<X509Certificate>): CertPath =
        certFactory().generateCertPath(chain)

    private fun certFactory(): CertificateFactory = CertificateFactory.getInstance(X509)
    private fun certPathValidator() = CertPathValidator.getInstance(PKIX)
}
