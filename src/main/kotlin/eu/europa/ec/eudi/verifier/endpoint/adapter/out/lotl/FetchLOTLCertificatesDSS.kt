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

import eu.europa.ec.eudi.verifier.endpoint.port.out.lotl.FetchLOTLCertificates
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader
import eu.europa.esig.dss.spi.client.http.DSSCacheFileLoader
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource
import eu.europa.esig.dss.tsl.cache.CacheCleaner
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI
import eu.europa.esig.dss.tsl.job.TLValidationJob
import eu.europa.esig.dss.tsl.sha2.Sha2FileCacheDataLoader
import eu.europa.esig.dss.tsl.source.LOTLSource
import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.File
import java.net.URL
import java.security.cert.X509Certificate

class FetchLOTLCertificatesDSS() : FetchLOTLCertificates {

    private val logger: Logger = LoggerFactory.getLogger(FetchLOTLCertificatesDSS::class.java)

    override suspend fun invoke(lotlUrl: URL): Result<List<X509Certificate>> = runCatching {
        val trustedListsCertificateSource = TrustedListsCertificateSource()

        val tlCacheDirectory = File(System.getProperty("java.io.tmpdir")) // TODO GD: make configurable

        val offlineLoader: DSSCacheFileLoader = FileCacheDataLoader().apply {
            setCacheExpirationTime(24 * 60 * 60 * 1000) // TODO GD: make configurable
            setFileCacheDirectory(tlCacheDirectory)
            dataLoader = IgnoreDataLoader()
        }

        val onlineLoader: DSSCacheFileLoader = FileCacheDataLoader().apply {
            setCacheExpirationTime(-1) // control cache by Sha2FileCacheDataLoader
            setFileCacheDirectory(tlCacheDirectory)
            dataLoader = CommonsDataLoader()
        }.also {
            Sha2FileCacheDataLoader.initSha2DailyUpdateDataLoader(it)
        }

        val cacheCleaner = CacheCleaner().apply {
            setCleanMemory(true)
            setCleanFileSystem(true)
            setDSSFileLoader(offlineLoader)
        }

        val validationJob = TLValidationJob().apply {
            setListOfTrustedListSources(europeanLOTL())
            setOfflineDataLoader(offlineLoader)
            setOnlineDataLoader(onlineLoader)
            setTrustedListCertificateSource(trustedListsCertificateSource)
            setSynchronizationStrategy(AcceptAllStrategy()) // TODO GD: could also be ExpirationAndSignatureCheckStrategy()
            setCacheCleaner(cacheCleaner)
        }

        logger.info("Starting validation job")
        validationJob.onlineRefresh()

        trustedListsCertificateSource.certificates.map {
            it.certificate
        }
    }
}

private const val europeanLOTLUrl = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
private const val officialJournalUrl = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG"

private fun europeanLOTL(): LOTLSource {
    val lotlSource = LOTLSource()
    lotlSource.url = europeanLOTLUrl
    // lotlSource.certificateSource = officialJournalContentKeyStore()// TODO GD: uncomment
    lotlSource.signingCertificatesAnnouncementPredicate = OfficialJournalSchemeInformationURI(officialJournalUrl)
    lotlSource.isPivotSupport = false
    lotlSource.tlVersions = listOf(5, 6)
    return lotlSource
}
