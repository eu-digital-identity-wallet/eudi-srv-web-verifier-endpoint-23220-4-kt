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

import arrow.core.getOrElse
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.TrustSources
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CValidator
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.assertDoesNotThrow
import kotlin.test.fail

/**
 * Kotlin issuer JWK
 */
val issuerJwkSet =
    """
        {
            "keys": [
              {
                "kty": "EC",
                "x5t#S256": "lepXgwwQ__hRUtrbwMqbxqtMKdnzgitViBulOKKlDPQ",
                "nbf": 1728554031,
                "use": "sig",
                "crv": "P-256",
                "kid": "pid ds - 006",
                "x5c": [
                  "MIIC4jCCAmmgAwIBAgIUaJK7OBpIQJ15sETltVo4Oe7zkbwwCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTI0MTAxMDA5NTM1MVoXDTI2MDEwMzA5NTM1MFowUzEVMBMGA1UEAwwMUElEIERTIC0gMDA2MS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXboaixZVp/52Qq0v4OdYHIJ/QQ0u7Re4rh7OXtk9shmgaCvTJkOEGgawEPFuoH1bDfyP4EPkSiXOrtpwAMdiRKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB/wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBRvpijzc7AgPsNYos4qpt66AbAGDDAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNnADBkAjBBkXCtr6HX8v9hdPqCZwL+75uurOWXUElNUW6GgXNfKBAFN24QQRzEde+Lt0TNZxYCMHkgTqhnfn4pXCRiMdv8qsA2ehnlcDkkQQlHkNEr5FSw5HJD2oIKUvk9dOqRvA9qRA=="
                ],
                "x": "XboaixZVp_52Qq0v4OdYHIJ_QQ0u7Re4rh7OXtk9shk",
                "y": "oGgr0yZDhBoGsBDxbqB9Ww38j-BD5Eolzq7acADHYkQ",
                "exp": 1767434030
              }
            ]
         }
    """.trimIndent()

/**
 * A kotlin issued credential, presented by android wallet
 */
val presentation =
    """
        {
          "key": "wallet_response",
          "value": {
            "vp_token": [
              "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBld2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xbGlzc3VlclNpZ25lZKJqbmFtZVNwYWNlc6F3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjGB2BhYT6RmcmFuZG9tUEXjK7Y2ozEyo1cV38gioLxoZGlnZXN0SUQEbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMThqaXNzdWVyQXV0aIRDoQEmoRghWQLmMIIC4jCCAmmgAwIBAgIUaJK7OBpIQJ15sETltVo4Oe7zkbwwCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTI0MTAxMDA5NTM1MVoXDTI2MDEwMzA5NTM1MFowUzEVMBMGA1UEAwwMUElEIERTIC0gMDA2MS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXboaixZVp_52Qq0v4OdYHIJ_QQ0u7Re4rh7OXtk9shmgaCvTJkOEGgawEPFuoH1bDfyP4EPkSiXOrtpwAMdiRKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBRvpijzc7AgPsNYos4qpt66AbAGDDAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNnADBkAjBBkXCtr6HX8v9hdPqCZwL-75uurOWXUElNUW6GgXNfKBAFN24QQRzEde-Lt0TNZxYCMHkgTqhnfn4pXCRiMdv8qsA2ehnlcDkkQQlHkNEr5FSw5HJD2oIKUvk9dOqRvA9qRFkDktgYWQONpmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xsABYIISopvEiMTD6UAMrJ5lonKwDaAfeocslSwz9C77lqo9jAVgg04n_N2pZZRmZu7WSyf3jpwTHaanL-gAlUEQEtkm20fMCWCACqny1LcoRuLIcQeRnFYVmg5BxE7NLJW6Wv7s-laujcQNYIJ6gZtEkkqRyF3xgytoHsWQw1lkRmmAlKFl2GQCXtO8kBFggIN5ygByNwfvO5BGkp8V5WQmWhotd1Cc_7km7-YBmWZsFWCDtsQtSKoaIwyFpuoMsF2bq5alkZ6A8nsuQ6cjp9DK_aQZYICNQ7MIlnzAwHN_ZNSan7m3Dw1isOGseX4-s9rhhsZ_ZB1ggPVpASuGsxDCE67L1wySHy5mkxwC4lR8c-OWJL6xSkEoIWCCX15QP5WFu8Nkd1lz_Kmz5Xl63hGDJnRkQHBm1yX_hfQlYILzK5B4_YscodvPMYHFPq98Wi1T86WnDVJxJ9GZnSGo_ClggVEWmvhfDG1RmciC29spLFhZ1ro3JB0Vs7gfuza22lEILWCAMkABC69jIzOCGMPAXT4oGsktVEQR11O-jkJmsWecguQxYIHu_cEW0m1jXanDGclvBD6Qs8ItwEfG3Yhmr-5tJnAJdDVggEs4oE3XYwkytwPrn25cK6cGHS3TSjXXMdH2bPjl4-skOWCBgI846KOSp9lZQufDjCWLaJ98r0W9HotJ1P8EnVQ23IA9YIDd2IfF_LuqJrYmqGnwi1E_Bcaxek2lt6TfXd6ZsicQtbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggaXqhrYpkfmtXeeqvRy2Dz3IAnyAJlyR-T9_sltd1HoUiWCBktRkYNObdYEQb8o8lH9lRriMpkIjtDADQxSkistiAWGdkb2NUeXBld2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHgeMjAyNC0xMC0xMVQwNzoyOToxMi43NTMwODkyMTRaaXZhbGlkRnJvbcB4HjIwMjQtMTAtMTFUMDc6Mjk6MTIuNzUzMDg5MjE0Wmp2YWxpZFVudGlswHgeMjAyNC0xMS0xMFQwNzoyOToxMi43NTMwODkyMTRaWEDwrKDUD7KRPFuZaXsbyU_EV60P36qjUQyoHnoeaUBo99oNZ8jIwOsAoFQ_S-JSmddlsbdrLAjLRUjBQkFkpfKebGRldmljZVNpZ25lZKJqbmFtZVNwYWNlc9gYQaBqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhAIqtDVriPApFjL3jWiWwK0rejVK95wJ5UyqUjiY03YmQehGQ9kk1AEzED0I7JlxlIWtrdK6R4DpwJJw82NJ14bWZzdGF0dXMA"
            ],
            "presentation_submission": {
              "id": "305be5b1-a683-4a97-b04b-3d7e3fad42c5",
              "definition_id": "9f39e0ab-175c-48b9-a9d7-58e66f482810",
              "descriptor_map": [
                {
                  "id": "eu.europa.ec.eudi.pid.1",
                  "format": "mso_mdoc",
                  "path": "${'$'}"
                }
              ]
            }
          }
        }
    """.trimIndent()

val trusted: X5CShouldBe.Trusted by lazy {
    X5CShouldBe.Trusted(Data.caCerts)
}
val trustSources = TrustSources().apply {
    updateWithX5CShouldBe(
        Regex(".*"),
        trusted,
    )
}

fun checkIssuerJwkSet() {
    val chain = run {
        val jwkSet = JWKSet.load(issuerJwkSet.byteInputStream())
        val jwk = jwkSet.keys.first()
        checkNotNull(jwk.parsedX509CertChain.toNonEmptyListOrNull())
    }
    val chainValidator = X5CValidator(trusted)
    chainValidator.trustedOrThrow(chain)
}

fun main() {
    val vpToken = Json.parseToJsonElement(presentation)
        .jsonObject["value"]!!
        .jsonObject["vp_token"]!!
        .jsonArray
        .first()
        .jsonPrimitive.content

    val devRespValidator = DeviceResponseValidator(
        DocumentValidator(
            validityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
            trustSources = trustSources,
            issuerSignedItemsShouldBe = IssuerSignedItemsShouldBe.Verified,
        ),
    )
    val validated = devRespValidator.ensureValid(vpToken)

    val docs =
        assertDoesNotThrow {
            validated.getOrElse { fail(it.toString()) }
        }
}
