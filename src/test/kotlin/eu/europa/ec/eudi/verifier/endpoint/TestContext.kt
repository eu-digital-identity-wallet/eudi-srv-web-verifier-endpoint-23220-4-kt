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
package eu.europa.ec.eudi.verifier.endpoint

import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.GenerateEphemeralEncryptionKeyPairNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.ParseJarmOptionNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.SignRequestObjectNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption.ByValue
import eu.europa.ec.eudi.verifier.endpoint.port.input.GetRequestObject
import eu.europa.ec.eudi.verifier.endpoint.port.input.GetRequestObjectLive
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransaction
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionLive
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GeneratePresentationId
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateRequestId
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.*

object TestContext {
    val testDate = LocalDate.of(1974, 11, 2).atTime(10, 5, 33)
    val testClock = Clock.fixed(testDate.toInstant(ZoneOffset.UTC), ZoneOffset.UTC)
    val testPresentationId = PresentationId("SamplePresentationId")
    val generatedPresentationId = GeneratePresentationId.fixed(testPresentationId)
    val testRequestId = RequestId("SampleRequestId")
    val generateRequestId = GenerateRequestId.fixed(testRequestId)
    val rsaJwk = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
        .issueTime(Date()) // issued-at timestamp (optional)
        .generate()
    val clientMetaData = ClientMetaData(
        jwkOption = ByValue,
        idTokenSignedResponseAlg = "RS256",
        idTokenEncryptedResponseAlg = "RS256",
        idTokenEncryptedResponseEnc = "A128CBC-HS256",
        subjectSyntaxTypesSupported = listOf("urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key"),
        jarmOption = ParseJarmOptionNimbus(null, "ECDH_ES", "A256GCM")!!,
    )
    val singRequestObject: SignRequestObjectNimbus = SignRequestObjectNimbus(rsaJwk)
    val singRequestObjectVerifier = RSASSAVerifier(rsaJwk.toRSAPublicKey())
    private val repo = PresentationInMemoryRepo()
    val loadPresentationById = repo.loadPresentationById
    val loadPresentationByRequestId = repo.loadPresentationByRequestId
    val storePresentation = repo.storePresentation
    val generateEphemeralKey = GenerateEphemeralEncryptionKeyPairNimbus

    fun initTransaction(verifierConfig: VerifierConfig): InitTransaction =
        InitTransactionLive(
            generatedPresentationId,
            generateRequestId,
            storePresentation,
            singRequestObject,
            verifierConfig,
            testClock,
            generateEphemeralKey,
        )
    fun getRequestObject(verifierConfig: VerifierConfig, presentationInitiatedAt: Instant): GetRequestObject =
        GetRequestObjectLive(
            loadPresentationByRequestId,
            storePresentation,
            singRequestObject,
            verifierConfig,
            Clock.fixed(presentationInitiatedAt.plusSeconds(1 * 60), testClock.zone),
        )
}
