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

sealed interface DocumentError {
    data object MissingIssuerAuth : DocumentError
    data object MissingX5ChainFromIssuerAuth : DocumentError
    data class InvalidChain(val cause: String?) : DocumentError
    data object InvalidIssuerSignature : DocumentError
    data object MissingValidity : DocumentError
    data class InvalidValidity(val validFrom: Instant, val validTo: Instant) : DocumentError
    data object InvalidDocumentType : DocumentError
    data object InvalidIssuerSignedItems : DocumentError
}

enum class ValidityInfoOption {
    Required,
    ValidIfPresent
}

sealed interface ChainOption {
    data class Trusted(val trustedRootCAs: Nel<X509Certificate>) : ChainOption
    data object SkipValidation : ChainOption
}

class MsoMdocDocumentValidator(
    private val clock: Clock = Clock.systemDefaultZone(),
    private val validityInfoOption: ValidityInfoOption = ValidityInfoOption.Required,
    private val chainOption: ChainOption,
) {

    fun ensureValidDocument(document: MDoc): EitherNel<DocumentError, MDoc> {
        val chain =
            either {
                ensureTrustedChain(document, chainOption)
            }

        return either {
            zipOrAccumulate(
                { verifyValidity(document, clock, validityInfoOption) },
                { verifyDocType(document) },
                { verifyIssuerSignedItems(document) },
                { verifyIssuerSignature(document, chain.bind()) },
            ) { _, _, _, _ -> document }
        }
    }

    companion object {
        fun fromKeystore(
            clock: Clock = Clock.systemDefaultZone(),
            validityInfoOption: ValidityInfoOption = ValidityInfoOption.Required,
            trustedCAsKeyStore: KeyStore
        ): MsoMdocDocumentValidator {
            val trustedRootCAs = trustedCAs(trustedCAsKeyStore).toNonEmptyListOrNull()
            requireNotNull(trustedRootCAs) { "Couldn't find certificates in the keystore" }
            val chainOption  = ChainOption.Trusted(trustedRootCAs)
            return MsoMdocDocumentValidator(clock, validityInfoOption, chainOption)
        }

        private fun trustedCAs(keystore: KeyStore): List<X509Certificate> {
            fun x509(alias: String) = alias.takeIf(keystore::isCertificateEntry)
                ?.let(keystore::getCertificate) as? X509Certificate

            return buildList {
                for (alias in keystore.aliases()) {
                    x509(alias)?.let(::add)
                }
            }
        }
    }
}

internal fun Raise<DocumentError>.verifyValidity(
    document: MDoc,
    clock: Clock,
    validityInfoOption: ValidityInfoOption
) {
    fun check(vi: ValidityInfo) {
        val validFrom = vi.validFrom.value.toJavaInstant()
        val validTo = vi.validUntil.value.toJavaInstant()
        val now = clock.instant()
        ensure(validFrom <= now && validTo >= now) {
            DocumentError.InvalidValidity(validFrom, validTo)
        }


    }

    val validityInfo = document.MSO?.validityInfo
    when (validityInfoOption) {
        ValidityInfoOption.Required -> {
            ensureNotNull(validityInfo) {
                DocumentError.MissingValidity
            }
            check(validityInfo)
        }

        ValidityInfoOption.ValidIfPresent -> validityInfo?.let(::check)
    }
}

internal fun Raise<DocumentError.InvalidDocumentType>.verifyDocType(document: MDoc) =
    ensure(document.verifyDocType()) {
        DocumentError.InvalidDocumentType
    }

internal fun Raise<DocumentError>.verifyIssuerSignature(document: MDoc, chain: NonEmptyList<X509Certificate>) {
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


internal fun Raise<DocumentError>.verifyIssuerSignedItems(document: MDoc) =
    ensure(document.verifyIssuerSignedItems()) {
        DocumentError.InvalidIssuerSignedItems
    }


internal fun Raise<DocumentError>.ensureTrustedChain(
    document: MDoc,
    chainOption: ChainOption,
): NonEmptyList<X509Certificate> {
    val issuerAuth: COSESign1 =
        ensureNotNull(document.issuerSigned.issuerAuth) { DocumentError.MissingIssuerAuth }
    val chain = run {
        val x5c = ensureNotNull(issuerAuth.x5Chain) { DocumentError.MissingX5ChainFromIssuerAuth }
        val factory: CertificateFactory = CertificateFactory.getInstance("X.509")
        factory.generateCertificates(x5c.inputStream()) as List<X509Certificate>
    }
    val chainNel = ensureNotNull(chain.toNonEmptyListOrNull()) {
        DocumentError.MissingX5ChainFromIssuerAuth
    }
    return when (chainOption) {
        ChainOption.SkipValidation -> chainNel
        is ChainOption.Trusted -> ensureTrustedChain(chainNel, chainOption)
    }

}

fun Raise<DocumentError.InvalidChain>.ensureTrustedChain(
    chain: Nel<X509Certificate>,
    trust: ChainOption.Trusted,
): Nel<X509Certificate> =
    try {
        CertValidationOps.validateChain(chain, trust.trustedRootCAs)
        chain
    } catch (e: CertPathValidatorException) {
        raise(DocumentError.InvalidChain(e.message))
    }
