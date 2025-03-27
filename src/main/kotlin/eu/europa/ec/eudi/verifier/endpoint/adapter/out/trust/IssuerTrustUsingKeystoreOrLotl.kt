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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.trust

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.sdjwt.vc.Vct
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.domain.MsoMdocDocType
import eu.europa.ec.eudi.verifier.endpoint.port.out.trust.IssuerTrust
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.URI
import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.cert.X509Certificate
import java.security.KeyStore as JavaKeyStore

/**
 * [IssuerTrust] implementation that can use Keystores and/or LOTLs.
 */
class IssuerTrustUsingKeystoreOrLotl private constructor(
    private val issuers: Map<TrustedIssuer, NonEmptyList<CertificateSourceManager>>,
) : IssuerTrust {
    private val mutex = Mutex(locked = false)

    override suspend fun getTrustedIssuers(vct: Vct): X5CShouldBe =
        mutex.withLock {
            issuers.entries.firstOrNull {
                    (issuer, _) ->
                issuer is TrustedIssuer.SdJwtVc && vct.value.startsWith(issuer.vctStartsWith.value)
            }
                ?.let { (_, managers) ->
                    val certificates = managers.getCertificates().toNonEmptyListOrNull()
                    certificates?.let { X5CShouldBe(it) }
                } ?: X5CShouldBe.Ignored
        }

    override suspend fun getTrustedIssuers(docType: MsoMdocDocType): X5CShouldBe =
        mutex.withLock {
            issuers.entries.firstOrNull {
                    (issuer, _) ->
                issuer is TrustedIssuer.MsoMDoc && docType.value.startsWith(issuer.docTypeStartsWith.value)
            }
                ?.let { (_, managers) ->
                    val certificates = managers.getCertificates().toNonEmptyListOrNull()
                    certificates?.let { X5CShouldBe(it) }
                } ?: X5CShouldBe.Ignored
        }

    suspend fun refresh() {
        coroutineScope {
            mutex.withLock {
                val managers = issuers.flatMap { it.value }
                val results = managers.map { manager -> launch { manager.refresh() } }
                results.joinAll()
            }
        }
    }

    companion object {
        operator fun invoke(issuers: NonEmptyList<TrustedIssuer>): IssuerTrustUsingKeystoreOrLotl =
            IssuerTrustUsingKeystoreOrLotl(
                issuers.associateWith { issuer -> issuer.certificateSources.map { CertificateSourceManager(it) } },
            )
    }
}

private suspend fun Collection<CertificateSourceManager>.getCertificates(): List<X509Certificate> =
    flatMap { it.getCertificates() }.distinct()

sealed interface TrustedIssuer {
    val certificateSources: NonEmptyList<CertificateSource>

    data class SdJwtVc(
        val vctStartsWith: Vct,
        override val certificateSources: NonEmptyList<CertificateSource>,
    ) : TrustedIssuer

    data class MsoMDoc(
        val docTypeStartsWith: MsoMdocDocType,
        override val certificateSources: NonEmptyList<CertificateSource>,
    ) : TrustedIssuer
}

sealed interface CertificateSource {
    data class KeyStore(val location: Path, val type: String, val password: String?) : CertificateSource
    data class LOTL(val location: URL, val serviceType: URI) : CertificateSource
}

private sealed interface CertificateSourceManager {
    suspend fun refresh()
    suspend fun getCertificates(): List<X509Certificate>

    companion object {
        operator fun invoke(certificateSource: CertificateSource): CertificateSourceManager =
            when (certificateSource) {
                is CertificateSource.KeyStore -> KeyStoreManager(certificateSource)
                is CertificateSource.LOTL -> LotlManager(certificateSource)
            }
    }
}

private class KeyStoreManager(
    private val keyStore: CertificateSource.KeyStore,
) : CertificateSourceManager {
    private val mutex = Mutex()
    private var certificates: List<X509Certificate> = emptyList()

    override suspend fun refresh() {
        fun JavaKeyStore.getX509Certificate(alias: String): X509Certificate? =
            if (isCertificateEntry(alias)) getCertificate(alias) as? X509Certificate
            else null

        withContext(Dispatchers.IO) {
            mutex.withLock {
                certificates = Files.newInputStream(keyStore.location, StandardOpenOption.READ)
                    .use { inputStream ->
                        val javaKeystore = JavaKeyStore.getInstance(keyStore.type)
                        javaKeystore.load(inputStream, keyStore.password?.toCharArray())
                        buildList {
                            for (alias in javaKeystore.aliases()) {
                                javaKeystore.getX509Certificate(alias)?.let(::add)
                            }
                        }
                    }
            }
        }
    }

    override suspend fun getCertificates(): List<X509Certificate> =
        mutex.withLock {
            certificates
        }
}

private class LotlManager(private val lotl: CertificateSource.LOTL) : CertificateSourceManager {
    private val mutex = Mutex()

    override suspend fun refresh() {
        mutex.withLock {
            TODO("Not yet implemented")
        }
    }

    override suspend fun getCertificates(): List<X509Certificate> =
        mutex.withLock {
            TODO("Not yet implemented")
        }
}
