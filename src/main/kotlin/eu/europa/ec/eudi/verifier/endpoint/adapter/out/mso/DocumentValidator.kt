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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso

import COSE.AlgorithmID
import arrow.core.*
import arrow.core.raise.*
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CValidator
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.cose.COSESign1
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.datetime.toJavaInstant
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant

enum class ValidityInfoShouldBe {
    NotExpired,
    NotExpiredIfPresent,
    Ignored,
}

enum class IssuerSignedItemsShouldBe {
    Verified,
    Ignored,
}

sealed interface DocumentError {
    data object MissingValidityInfo : DocumentError
    data class ExpiredValidityInfo(val validFrom: Instant, val validTo: Instant) : DocumentError
    data object InvalidIssuerSignature : DocumentError
    data class X5CNotTrusted(val cause: String?) : DocumentError
    data object DocumentTypeNotMatching : DocumentError
    data object InvalidIssuerSignedItems : DocumentError
}

class DocumentValidator(
    private val clock: Clock = Clock.systemDefaultZone(),
    private val validityInfoShouldBe: ValidityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
    private val issuerSignedItemsShouldBe: IssuerSignedItemsShouldBe = IssuerSignedItemsShouldBe.Verified,
    private val x5CShouldBe: X5CShouldBe,
) {

    fun ensureValid(document: MDoc): EitherNel<DocumentError, MDoc> =
        either {
            val issuerChain = ensureTrustedChain(document, x5CShouldBe)
            zipOrAccumulate(
                { ensureNotExpiredValidityInfo(document, clock, validityInfoShouldBe) },
                { ensureMatchingDocumentType(document) },
                { ensureDigestsOfIssuerSignedItems(document, issuerSignedItemsShouldBe) },
                { ensureValidIssuerSignature(document, issuerChain, x5CShouldBe.caCertificates()) },
            ) { _, _, _, _ -> document }
        }

    companion object {
        fun fromKeystore(
            clock: Clock = Clock.systemDefaultZone(),
            validityInfoShouldBe: ValidityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
            issuerSignedItemsShouldBe: IssuerSignedItemsShouldBe = IssuerSignedItemsShouldBe.Verified,
            trustedCAsKeyStore: KeyStore,
        ): DocumentValidator {
            val trustedRootCAs = trustedCAs(trustedCAsKeyStore)
            val x5CShouldBe = X5CShouldBe(trustedRootCAs)
            return DocumentValidator(clock, validityInfoShouldBe, issuerSignedItemsShouldBe, x5CShouldBe)
        }

        private fun trustedCAs(keystore: KeyStore): List<X509Certificate> {
            fun x509(alias: String) =
                alias.takeIf(keystore::isCertificateEntry)
                    ?.let(keystore::getCertificate) as? X509Certificate

            return buildList {
                for (alias in keystore.aliases()) {
                    x509(alias)?.let(::add)
                }
            }
        }
    }
}

private fun Raise<DocumentError>.ensureNotExpiredValidityInfo(
    document: MDoc,
    clock: Clock,
    validityInfoShouldBe: ValidityInfoShouldBe,
) {
    fun ValidityInfo.notExpired() {
        val validFrom = validFrom.value.toJavaInstant()
        val validTo = validUntil.value.toJavaInstant()
        val now = clock.instant()
        ensure(now in validFrom..validTo) {
            DocumentError.ExpiredValidityInfo(validFrom, validTo)
        }
    }

    val validityInfo = document.MSO?.validityInfo
    when (validityInfoShouldBe) {
        ValidityInfoShouldBe.NotExpired ->
            ensureNotNull(validityInfo) { DocumentError.MissingValidityInfo }.notExpired()

        ValidityInfoShouldBe.NotExpiredIfPresent -> validityInfo?.notExpired()
        ValidityInfoShouldBe.Ignored -> Unit
    }
}

private fun Raise<DocumentError.DocumentTypeNotMatching>.ensureMatchingDocumentType(document: MDoc) =
    ensure(document.verifyDocType()) {
        DocumentError.DocumentTypeNotMatching
    }

private const val ISSUER_KEY_ID = "ISSUER_KEY_ID"
private fun Raise<DocumentError.InvalidIssuerSignature>.ensureValidIssuerSignature(
    document: MDoc,
    chain: NonEmptyList<X509Certificate>,
    caCertificates: List<X509Certificate>,
) {
    val issuerKeyInfo = cryptoProviderKeyInfo(chain, caCertificates)
    val issuerCryptoProvider = SimpleCOSECryptoProvider(listOf(issuerKeyInfo))
    ensure(document.verifySignature(issuerCryptoProvider, issuerKeyInfo.keyID)) {
        DocumentError.InvalidIssuerSignature
    }
}

private fun cryptoProviderKeyInfo(
    chain: NonEmptyList<X509Certificate>,
    caCertificates: List<X509Certificate>,
): COSECryptoProviderKeyInfo {
    val issuerCert = chain.head
    // TODO find a way to not hard-code algorithm
    return COSECryptoProviderKeyInfo(
        keyID = ISSUER_KEY_ID,
        algorithmID = AlgorithmID.ECDSA_256,
        publicKey = issuerCert.publicKey,
        privateKey = null,
        x5Chain = chain,
        trustedRootCAs = caCertificates,
    )
}

private fun Raise<DocumentError.InvalidIssuerSignedItems>.ensureDigestsOfIssuerSignedItems(
    document: MDoc,
    issuerSignedItemsShouldBe: IssuerSignedItemsShouldBe,
) = when (issuerSignedItemsShouldBe) {
    IssuerSignedItemsShouldBe.Verified ->
        ensure(document.verifyIssuerSignedItems()) { DocumentError.InvalidIssuerSignedItems }

    IssuerSignedItemsShouldBe.Ignored -> {}
}

private fun Raise<Nel<DocumentError.X5CNotTrusted>>.ensureTrustedChain(
    document: MDoc,
    x5CShouldBe: X5CShouldBe,
): NonEmptyList<X509Certificate> {
    val issuerAuth: COSESign1 =
        ensureNotNull(document.issuerSigned.issuerAuth) { DocumentError.X5CNotTrusted("Missing issuerAuth").nel() }
    val chain = run {
        val x5c = ensureNotNull(issuerAuth.x5Chain) { DocumentError.X5CNotTrusted("Missing x5Chain").nel() }
        val factory: CertificateFactory = CertificateFactory.getInstance("X.509")
        factory.generateCertificates(x5c.inputStream()).mapNotNull { it as? X509Certificate }.toNonEmptyListOrNull()
    }

    ensureNotNull(chain) { DocumentError.X5CNotTrusted("Empty chain").nel() }

    val x5cValidator = X5CValidator(x5CShouldBe)
    val trustedChain = x5cValidator.ensureTrusted(chain).mapLeft { exception ->
        DocumentError.X5CNotTrusted(exception.message).nel()
    }
    return trustedChain.bind()
}
