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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.lotl

import eu.europa.ec.eudi.verifier.endpoint.domain.TrustSourceConfig
import eu.europa.ec.eudi.verifier.endpoint.port.out.lotl.FetchLOTLCertificates
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader
import eu.europa.esig.dss.spi.client.http.DSSCacheFileLoader
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import eu.europa.esig.dss.tsl.cache.CacheCleaner
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate
import eu.europa.esig.dss.tsl.job.TLValidationJob
import eu.europa.esig.dss.tsl.source.LOTLSource
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType
import kotlinx.coroutines.Dispatchers
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.core.io.DefaultResourceLoader
import java.io.File
import java.net.URL
import java.security.cert.X509Certificate
import java.util.function.Predicate

private val logger: Logger = LoggerFactory.getLogger(FetchLOTLCertificatesDSS::class.java)

class FetchLOTLCertificatesDSS() : FetchLOTLCertificates {

    override suspend fun invoke(
        url: URL,
        serviceTypeFilter: String?,
        keystoreConfig: TrustSourceConfig.KeyStoreConfig?,
    ): Result<List<X509Certificate>> =
        with(Dispatchers.IO.limitedParallelism(1)) {
            runCatching {
                val trustedListsCertificateSource = TrustedListsCertificateSource()

                val tlCacheDirectory = File(System.getProperty("java.io.tmpdir")) // TODO GD: make configurable

                val offlineLoader: DSSCacheFileLoader = FileCacheDataLoader().apply {
                    setCacheExpirationTime(24 * 60 * 60 * 1000)
                    setFileCacheDirectory(tlCacheDirectory)
                    dataLoader = IgnoreDataLoader()
                }

                val onlineLoader: DSSCacheFileLoader = FileCacheDataLoader().apply {
                    setCacheExpirationTime(24 * 60 * 60 * 1000)
                    setFileCacheDirectory(tlCacheDirectory)
                    dataLoader = CommonsDataLoader()
                }

                val cacheCleaner = CacheCleaner().apply {
                    setCleanMemory(true)
                    setCleanFileSystem(true)
                    setDSSFileLoader(offlineLoader)
                }

                val validationJob = TLValidationJob().apply {
                    setListOfTrustedListSources(lotlSource(url, serviceTypeFilter, keystoreConfig))
                    setOfflineDataLoader(offlineLoader)
                    setOnlineDataLoader(onlineLoader)
                    setTrustedListCertificateSource(trustedListsCertificateSource)
                    setSynchronizationStrategy(ExpirationAndSignatureCheckStrategy())
                    setCacheCleaner(cacheCleaner)
                }

                logger.info("Starting validation job")
                validationJob.onlineRefresh()

                trustedListsCertificateSource.certificates.map {
                    it.certificate
                }
            }
        }
}

private fun lotlSource(
    url: URL,
    serviceTypeFilter: String?,
    keystoreConfig: TrustSourceConfig.KeyStoreConfig?,
): LOTLSource {
    val lotlSource = LOTLSource()
    lotlSource.url = url.toString()
    keystoreConfig?.let {
        lotlSource.certificateSource = lotlCertificateSource(it).getOrNull()
    }
    lotlSource.isPivotSupport = true
    lotlSource.trustAnchorValidityPredicate = GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate()
    lotlSource.tlVersions = listOf(5, 6)
    serviceTypeFilter?.let {
        lotlSource.trustServicePredicate = trustServicePredicate(it)
    }

    return lotlSource
}

fun lotlCertificateSource(keystoreConfig: TrustSourceConfig.KeyStoreConfig) = runCatching {
    KeyStoreCertificateSource(
        DefaultResourceLoader().getResource(keystoreConfig.keystorePath).inputStream,
        keystoreConfig.keystoreType,
        keystoreConfig.keystorePassword,
    )
}

private fun trustServicePredicate(serviceTypeFilter: String): Predicate<TSPServiceType> =
    Predicate<TSPServiceType> { tspServiceType ->
        tspServiceType.serviceInformation.serviceTypeIdentifier == serviceTypeFilter
    }
