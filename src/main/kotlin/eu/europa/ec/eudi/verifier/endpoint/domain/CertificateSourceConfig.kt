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

/*

verifier.trusted-issuers:
  - format: sd-jwt
    vctStartsWith: "urn:eu.europa.ec.eudi:pid:1"
    certificate-sources:
      - type: keystore
        location: file:///trusted-pid-providers.jks
        keystore-type: JKS
        password: changeit
      - type: lotl
        location: https://ec.europa.eu/tools/lotl/eu-lotl.xml
        service-type: http://uri.etsi.org/TrstSvc/Svctype/CA/QC

  - format: mso-mdoc
    docTypeStartsWith: org.iso.18013.5.1.mDL
    certificate-sources:
      - type: keystore
        location: file:///trusted-mdl-providers.jks
        keystore-type: JKS
        password: changeit
      - type: lotl
        location: https://ec.europa.eu/tools/lotl/eu-lotl.xml
        service-type: http://uri.etsi.org/TrstSvc/Svctype/CA/QC
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
