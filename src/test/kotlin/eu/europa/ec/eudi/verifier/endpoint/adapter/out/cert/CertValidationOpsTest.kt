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

import arrow.core.nonEmptyListOf
import arrow.core.nonEmptySetOf
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import java.security.cert.CertPathValidatorException
import java.security.cert.X509Certificate
import kotlin.test.Test

data class TrustedCA(val trustCert: X509Certificate, val caCert: X509Certificate)

object Sample {
    private const val signAlg = "SHA256withECDSA"

    fun create(): Pair<TrustedCA, X509Certificate> {
        //
        // Trust Anchor
        //
        val name: X500Name =
            X500NameBuilder(BCStyle.INSTANCE).apply {
                addRDN(BCStyle.C, "GR")
                addRDN(BCStyle.ST, "Attika")
                addRDN(BCStyle.L, "Marousi")
                addRDN(BCStyle.O, "Netcompany")
                addRDN(BCStyle.CN, "Demo Root Certificate")
            }.build()
        val (trustKeyPair, trustCertHolder) = CertificateOps.genTrustAnchor(signAlg, name)
        val trustCert = trustCertHolder.toCertificate()

        //
        // CA
        //
        val caSubject =
            X500NameBuilder(BCStyle.INSTANCE).apply {
                addRDN(BCStyle.C, "GR")
                addRDN(BCStyle.ST, "Attika")
                addRDN(BCStyle.L, "Marousi")
                addRDN(BCStyle.O, "Netcompany")
                addRDN(BCStyle.CN, "Demo Intermediate Certificate")
            }.build()
        val (caKeyPair, caCertHolder) =
            CertificateOps.genIntermediateCertificate(
                trustCertHolder,
                trustKeyPair.private,
                signAlg,
                0,
                caSubject,
            )
        val caCert = caCertHolder.toCertificate()

        //
        // End Entity
        //
        val eeSubject =
            X500NameBuilder(BCStyle.INSTANCE).apply {
                addRDN(BCStyle.C, "GR")
                addRDN(BCStyle.ST, "Attika")
                addRDN(BCStyle.L, "Marousi")
                addRDN(BCStyle.O, "Netcompany")
                addRDN(BCStyle.CN, "Demo End-Entity Certificate")
            }.build()
        val (_, eeCertHolder) = CertificateOps.genEndEntity(caCertHolder, caKeyPair.private, signAlg, eeSubject)
        val eeCert = eeCertHolder.toCertificate()

        return TrustedCA(trustCert, caCert) to eeCert
    }
}

@DisplayName("validateChain, when")
class CertValidationOpsTest {
    val entities = Sample.create()
    val trustedCA = entities.first
    val eeCertificate = entities.second

    @Test
    fun `chain contains end-entity and CA certs should succeed`() {
        // Chain contains end-entity and CA certs
        // trust contains the trust anchor cert
        val chain = nonEmptyListOf(eeCertificate, trustedCA.caCert)
        val trust = nonEmptyListOf(trustedCA.trustCert)
        assertDoesNotThrow { CertValidationOps.validateChain(chain, trust) }
    }

    @Test
    fun `chain contains end-entity CA and Trust certs should succeed`() {
        // Chain contains end-entity, CA and Trust Anchor certs
        // trust contains the trust anchor cert
        val chain = nonEmptyListOf(
            eeCertificate,
            trustedCA.caCert,
            trustedCA.trustCert,
        )
        val trust = nonEmptyListOf(trustedCA.trustCert)
        assertDoesNotThrow { CertValidationOps.validateChain(chain, trust) }
    }

    @Test
    fun `chain contain end-entity cert, trust contains CA and Trust certs then should succeed`() {
        // Chain contains end-entity
        // trust contains the CA and Trust Anchor certs
        val chain = nonEmptyListOf(eeCertificate)
        val trust = nonEmptyListOf(trustedCA.caCert, trustedCA.trustCert)
        assertDoesNotThrow { CertValidationOps.validateChain(chain, trust) }
    }

    @Test
    fun `cert order in chain should not affect validation`() {
        val chain = nonEmptyListOf(trustedCA.caCert, eeCertificate)
        val trust = nonEmptyListOf(trustedCA.trustCert)
        assertDoesNotThrow { CertValidationOps.validateChain(chain, trust) }
    }

    @Test
    fun `validate a partial chain should fail`() {
        val chain = nonEmptyListOf(eeCertificate)
        val trust = nonEmptyListOf(trustedCA.trustCert)
        assertThrows<CertPathValidatorException> { CertValidationOps.validateChain(chain, trust) }
    }

    @Test
    fun `when directly trusting the CA should succeed `() {
        val chain = nonEmptyListOf(eeCertificate)
        val trust = nonEmptyListOf(trustedCA.caCert)
        assertDoesNotThrow { CertValidationOps.validateChain(chain, trust) }
    }
}
