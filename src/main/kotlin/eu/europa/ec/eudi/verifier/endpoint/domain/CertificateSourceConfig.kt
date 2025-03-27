package eu.europa.ec.eudi.verifier.endpoint.domain

/*

verifier.certificate-sources:
  - matchers:
      - vctStartsWith: eu.europa.ec.eudi.pid
    lotl:
      location: https://ec.europa.eu/tools/lotl/eu-lotl.xml
      service-type-filter: https//.../EEA/P
      **public keys validation**
    keystore:
      location: classpath:trusted-pid-providers.jks
      type: JKS
      password: changeit
  - matchers:
      - docTypeStartsWith: org.iso.18013.5.1.mDL
    source: keystore
    keystore:
      location: classpath:trusted-issuers.jks
      type: JKS
      password: changeit

*/

enum class CertificateSourceType {
    KEYSTORE, LOTL
}

sealed interface CertificateSource {

    val matcher: List<MatcherRule>

    data class Lotl(val location: String, override val matcher: List<MatcherRule>) : CertificateSource
    data class Keystore(val location: String, val password: String, override val matcher: List<MatcherRule>) : CertificateSource
}

sealed interface MatcherRule {
    data class VctStartsWith(val prefix: String) : MatcherRule
    data class DocTypeStartsWith(val prefix: String) : MatcherRule
}