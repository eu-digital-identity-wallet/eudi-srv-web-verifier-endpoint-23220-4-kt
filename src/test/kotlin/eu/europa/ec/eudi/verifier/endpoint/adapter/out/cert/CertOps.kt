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

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.util.*
import kotlin.time.Duration

internal object CertificateOps {
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    private val clock = Clock.systemDefaultZone()

    private var serialNumberBase: Long = System.currentTimeMillis()

    @Synchronized
    private fun calculateSerialNumber(): BigInteger = BigInteger.valueOf(serialNumberBase++)

    private fun calculateDate(hoursInFuture: Int): Date {
        val secs = System.currentTimeMillis() / 1000
        return Date((secs + (hoursInFuture * 60 * 60)) * 1000)
    }

    private fun notBefore(d: Duration = Duration.ZERO): Instant =
        clock.instant().plusSeconds(d.inWholeSeconds)

    private val ecKeyPairGenerator: KeyPairGenerator by lazy {
        KeyPairGenerator.getInstance("EC", "BC")
    }

    private fun generateECPair(): KeyPair = ecKeyPairGenerator.genKeyPair()

    fun genTrustAnchor(
        sigAlg: String,
        name: X500Name,
    ): Pair<KeyPair, X509CertificateHolder> {
        val kp = ecKeyPairGenerator.genKeyPair()
        val certHolder = createTrustAnchor(kp, sigAlg, name)
        return kp to certHolder
    }

    fun genIntermediateCertificate(
        signerCert: X509CertificateHolder,
        signerKey: PrivateKey,
        sigAlg: String,
        followingCACerts: Int = 0,
        subject: X500Name,
    ): Pair<KeyPair, X509CertificateHolder> {
        val caKp = generateECPair()
        val caCertHolder =
            createIntermediateCertificate(signerCert, signerKey, sigAlg, caKp.public, followingCACerts, subject)
        return caKp to caCertHolder
    }

    fun genEndEntity(
        signerCert: X509CertificateHolder,
        signerKey: PrivateKey,
        sigAlg: String,
        subject: X500Name,
    ): Pair<KeyPair, X509CertificateHolder> {
        val eeKp = generateECPair()
        val eeCertHolder = createEndEntity(signerCert, signerKey, sigAlg, eeKp.public, subject)
        return eeKp to eeCertHolder
    }

    /**
     * Build a sample self-signed V1 certificate to use as a trust anchor, or
     *  root certificate.
     */
    fun createTrustAnchor(
        keyPair: KeyPair,
        sigAlg: String,
        name: X500Name,
    ): X509CertificateHolder {
        return JcaX509v1CertificateBuilder(
            name,
            calculateSerialNumber(),
            Date.from(notBefore()),
            calculateDate(24 * 31),
            name,
            keyPair.public,
        ).build(sigAlg, keyPair.private)
    }

    /**
     * Build a sample V3 intermediate certificate that can be used as a CA
     *  certificate.
     *  @param signerCert certificate carrying the public key that will late
     *  be used to verify this certificate's signature
     *  @param signerKey private key used to generate the signature in the certificate
     *  @param certKey public key to be installed in the certificate.
     */
    fun createIntermediateCertificate(
        signerCert: X509CertificateHolder,
        signerKey: PrivateKey,
        sigAlg: String,
        certKey: PublicKey,
        followingCACerts: Int = 0,
        subject: X500Name,
    ): X509CertificateHolder =
        JcaX509v3CertificateBuilder(
            signerCert.subject,
            calculateSerialNumber(),
            calculateDate(0),
            calculateDate(24 * 31),
            subject,
            certKey,
        ).apply {
            authorityKeyIdentifier(signerCert)
            subjectKeyIdentifier(certKey)
            basicConstraints(BasicConstraints(followingCACerts)) // allow this cert to sign other certs
            keyUsage(KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyCertSign or KeyUsage.cRLSign))
        }.build(sigAlg, signerKey)

    fun createEndEntity(
        signerCert: X509CertificateHolder,
        signerKey: PrivateKey,
        sigAlg: String,
        certKey: PublicKey,
        subject: X500Name,
    ): X509CertificateHolder =
        JcaX509v3CertificateBuilder(
            signerCert.subject,
            calculateSerialNumber(),
            Date.from(notBefore()),
            calculateDate(24 * 31),
            subject,
            certKey,
        ).apply {
            authorityKeyIdentifier(signerCert)
            subjectKeyIdentifier(certKey)
            basicConstraints(BasicConstraints(false)) // do not allow this cert to sign other certs
            keyUsage(KeyUsage(KeyUsage.digitalSignature))
        }.build(sigAlg, signerKey)
}

//
// Kotlin extensions
//

fun X509CertificateHolder.toCertificate(): X509Certificate {
    val cFact = CertificateFactory.getInstance("X.509", "BC")
    return cFact.generateCertificate(encoded.inputStream()) as X509Certificate
}

private fun JcaX509v1CertificateBuilder.build(sigAlg: String, privateKey: PrivateKey): X509CertificateHolder {
    val signer = signer(sigAlg, privateKey)
    return build(signer)
}

private fun JcaX509v3CertificateBuilder.build(sigAlg: String, privateKey: PrivateKey): X509CertificateHolder {
    val signer = signer(sigAlg, privateKey)
    return build(signer)
}

private fun JcaX509v3CertificateBuilder.authorityKeyIdentifier(signerCert: X509CertificateHolder) {
    addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(signerCert))
}

private fun JcaX509v3CertificateBuilder.subjectKeyIdentifier(certKey: PublicKey) {
    addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(certKey))
}

private fun JcaX509v3CertificateBuilder.keyUsage(keyUsage: KeyUsage) {
    addExtension(Extension.keyUsage, true, keyUsage)
}

/**
 * The BasicConstraints extension helps you to determine if the certificate containing it is allowed to
 * sign other certificates, and if so, what depth this can go to.
 *
 * So, for example, if cA is TRUE and the pathLenConstraint is 0, then the certificate, as far as this extension
 * is concerned, is allowed to sign other certificates, but none of the certificates so signed can be used to sign other certificates and lengthen
 * the chain.
 *
 */
private fun JcaX509v3CertificateBuilder.basicConstraints(c: BasicConstraints) {
    addExtension(Extension.basicConstraints, true, c)
}

private val extUtils = JcaX509ExtensionUtils()

private fun signer(sigAlg: String, privateKey: PrivateKey): ContentSigner =
    JcaContentSignerBuilder(sigAlg).setProvider("BC").build(privateKey)
