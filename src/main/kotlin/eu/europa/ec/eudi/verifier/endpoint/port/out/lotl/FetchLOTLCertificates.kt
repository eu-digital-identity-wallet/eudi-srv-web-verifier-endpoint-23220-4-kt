package eu.europa.ec.eudi.verifier.endpoint.port.out.lotl

import java.net.URL
import java.security.cert.X509Certificate

fun interface FetchLOTLCertificates {

    suspend operator fun invoke(
        lotlUrl: URL
    ): Result<List<X509Certificate>>
}