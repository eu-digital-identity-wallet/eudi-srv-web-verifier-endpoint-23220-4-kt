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
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.CertValidationOps
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.cose.COSESign1
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.datetime.toJavaInstant
import java.security.KeyStore
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant

enum class ValidityInfoShouldBe {
    NotExpired,
    NotExpiredIfPresent,
    Any,
}

sealed interface X5CShouldBe {
    data class Trusted(val trustedRootCAs: Nel<X509Certificate>) : X5CShouldBe
    data object Any : X5CShouldBe
}

sealed interface DocumentError {
    data class X5CNotTrusted(val cause: String?) : DocumentError
    data object InvalidIssuerSignature : DocumentError
    data object MissingValidity : DocumentError
    data class Expired(val validFrom: Instant, val validTo: Instant) : DocumentError
    data object InvalidDocumentType : DocumentError
    data object InvalidIssuerSignedItems : DocumentError
}

class DocumentValidator(
    private val clock: Clock = Clock.systemDefaultZone(),
    private val validityInfoShouldBe: ValidityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
    private val x5CShouldBe: X5CShouldBe,
) {

    fun ensureValidDocument(document: MDoc): EitherNel<DocumentError, MDoc> {
        val chain =
            either {
                ensureTrustedChain(document, x5CShouldBe)
            }

        return either {
            zipOrAccumulate(
                { verifyValidity(document, clock, validityInfoShouldBe) },
                { verifyDocType(document) },
                { verifyIssuerSignedItems(document) },
                { verifyIssuerSignature(document, chain.bind()) },
            ) { _, _, _, _ -> document }
        }
    }

    companion object {
        fun fromKeystore(
            clock: Clock = Clock.systemDefaultZone(),
            validityInfoShouldBe: ValidityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
            trustedCAsKeyStore: KeyStore,
        ): DocumentValidator {
            val trustedRootCAs = trustedCAs(trustedCAsKeyStore).toNonEmptyListOrNull()
            requireNotNull(trustedRootCAs) { "Couldn't find certificates in the keystore" }
            val x5CShouldBe = X5CShouldBe.Trusted(trustedRootCAs)
            return DocumentValidator(clock, validityInfoShouldBe, x5CShouldBe)
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

private fun Raise<DocumentError>.verifyValidity(
    document: MDoc,
    clock: Clock,
    validityInfoShouldBe: ValidityInfoShouldBe,
) {
    fun check(vi: ValidityInfo) {
        val validFrom = vi.validFrom.value.toJavaInstant()
        val validTo = vi.validUntil.value.toJavaInstant()
        val now = clock.instant()
        ensure(now in validFrom..validTo) {
            DocumentError.Expired(validFrom, validTo)
        }
    }

    val validityInfo = document.MSO?.validityInfo
    when (validityInfoShouldBe) {
        ValidityInfoShouldBe.NotExpired -> {
            ensureNotNull(validityInfo) {
                DocumentError.MissingValidity
            }
            check(validityInfo)
        }

        ValidityInfoShouldBe.NotExpiredIfPresent -> validityInfo?.let(::check)
        ValidityInfoShouldBe.Any -> Unit
    }
}

private fun Raise<DocumentError.InvalidDocumentType>.verifyDocType(document: MDoc) =
    ensure(document.verifyDocType()) {
        DocumentError.InvalidDocumentType
    }

private fun Raise<DocumentError>.verifyIssuerSignature(document: MDoc, chain: NonEmptyList<X509Certificate>) {
    // TODO find a way to not hard-code algorithm
    val issuerKeyInfo =
        COSECryptoProviderKeyInfo(
            keyID = "ISSUER_KEY_ID",
            algorithmID = AlgorithmID.ECDSA_256,
            publicKey = chain.head.publicKey,
            privateKey = null,
            x5Chain = chain,
            trustedRootCAs = emptyList(),
        )
    val issuerCryptoProvider = SimpleCOSECryptoProvider(listOf(issuerKeyInfo))
    ensure(document.verifySignature(issuerCryptoProvider, issuerKeyInfo.keyID)) {
        DocumentError.InvalidIssuerSignature
    }
}

private fun Raise<DocumentError>.verifyIssuerSignedItems(document: MDoc) =
    ensure(document.verifyIssuerSignedItems()) {
        DocumentError.InvalidIssuerSignedItems
    }

private fun Raise<DocumentError>.ensureTrustedChain(
    document: MDoc,
    x5CShouldBe: X5CShouldBe,
): NonEmptyList<X509Certificate> {
    val issuerAuth: COSESign1 =
        ensureNotNull(document.issuerSigned.issuerAuth) { DocumentError.X5CNotTrusted("Missing issuerAuth") }
    val chain = run {
        val x5c = ensureNotNull(issuerAuth.x5Chain) { DocumentError.X5CNotTrusted("Missing x5Chain") }
        val factory: CertificateFactory = CertificateFactory.getInstance("X.509")
        factory.generateCertificates(x5c.inputStream()).mapNotNull { it as? X509Certificate }.toNonEmptyListOrNull()
    }

    ensureNotNull(chain) { DocumentError.X5CNotTrusted("Empty chain") }

    return when (x5CShouldBe) {
        X5CShouldBe.Any -> chain
        is X5CShouldBe.Trusted -> ensureTrustedChain(chain, x5CShouldBe)
    }
}

private fun Raise<DocumentError.X5CNotTrusted>.ensureTrustedChain(
    chain: Nel<X509Certificate>,
    trust: X5CShouldBe.Trusted,
): Nel<X509Certificate> =
    try {
        CertValidationOps.validateChain(chain, trust.trustedRootCAs)
        chain
    } catch (e: CertPathValidatorException) {
        raise(DocumentError.X5CNotTrusted(e.message))
    }
