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

import arrow.core.nonEmptyListOf
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.RSAKey
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.CreateJarNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.GenerateEphemeralEncryptionKeyPairNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.ParseJarmOptionNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransaction
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionLive
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateTransactionId
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.context.support.GenericApplicationContext
import org.springframework.core.annotation.AliasFor
import org.springframework.core.io.ClassPathResource
import org.springframework.test.context.ContextConfiguration
import java.security.KeyStore
import java.time.Clock
import java.time.LocalDate
import java.time.ZoneOffset
import kotlin.reflect.KClass

object TestContext {
    private val testDate = LocalDate.of(1974, 11, 2).atTime(10, 5, 33)
    val testClock: Clock = Clock.fixed(testDate.toInstant(ZoneOffset.UTC), ZoneOffset.UTC)
    val testTransactionId = TransactionId("SampleTxId")
    private val generatedTransactionId = GenerateTransactionId.fixed(testTransactionId)
    val testRequestId = RequestId("SampleRequestId")
    private val generateRequestId = GenerateRequestId.fixed(testRequestId)
    private val rsaJwk = run {
        ClassPathResource("test-cert.jks").inputStream.use {
            val keystore = KeyStore.getInstance("JKS").apply {
                load(it, "".toCharArray())
            }
            RSAKey.load(keystore, "client-id", "".toCharArray())
        }
    }
    val clientMetaData = ClientMetaData(
        idTokenSignedResponseAlg = JWSAlgorithm.RS256.name,
        idTokenEncryptedResponseAlg = JWEAlgorithm.RSA_OAEP_256.name,
        idTokenEncryptedResponseEnc = EncryptionMethod.A128CBC_HS256.name,
        subjectSyntaxTypesSupported = listOf("urn:ietf:params:oauth:jwk-thumbprint", "did:example", "did:key"),
        jarmOption = ParseJarmOptionNimbus(null, JWEAlgorithm.ECDH_ES.name, "A256GCM")!!,
        vpFormats = VpFormats(
            VpFormat.SdJwtVc(nonEmptyListOf(JWSAlgorithm.ES256), nonEmptyListOf(JWSAlgorithm.ES256, JWSAlgorithm.RS256)),
            VpFormat.MsoMdoc(nonEmptyListOf(JWSAlgorithm.ES256)),
        ),
    )
    private val jarSigningConfig: SigningConfig = SigningConfig(rsaJwk, JWSAlgorithm.RS256)
    val verifierId = VerifierId.X509SanDns("client-id", jarSigningConfig)
    val createJar: CreateJarNimbus = CreateJarNimbus()
    val signedRequestObjectVerifier: JWSVerifier = RSASSAVerifier(rsaJwk)
    private val repo = PresentationInMemoryRepo()
    val loadPresentationById = repo.loadPresentationById
    private val storePresentation = repo.storePresentation
    private val generateEphemeralKey = GenerateEphemeralEncryptionKeyPairNimbus

    fun initTransaction(
        verifierConfig: VerifierConfig,
        requestJarByReference: EmbedOption.ByReference<RequestId>,
        presentationDefinitionByReference: EmbedOption.ByReference<RequestId>,
    ): InitTransaction =
        InitTransactionLive(
            generatedTransactionId,
            generateRequestId,
            storePresentation,
            createJar,
            verifierConfig,
            testClock,
            generateEphemeralKey,
            requestJarByReference,
            presentationDefinitionByReference,
            CreateQueryWalletResponseRedirectUri.Simple,
            repo.publishPresentationEvent,
        )
}

/**
 * Meta annotation to be used with integration tests of the application
 */
@Target(AnnotationTarget.CLASS)
@Retention(AnnotationRetention.RUNTIME)
@SpringBootTest(
    classes = [VerifierApplication::class],
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
)
@ContextConfiguration(initializers = [BeansDslApplicationContextInitializer::class])
internal annotation class VerifierApplicationTest(

    /**
     * [Configuration] classes that contain extra bean definitions.
     * Useful for bean overriding using [Primary] annotation.
     */
    @get:AliasFor(annotation = ContextConfiguration::class)
    val classes: Array<KClass<*>> = [],

)

/**
 * [ApplicationContextInitializer] for use with [SpringBootTest]/[ContextConfiguration]
 */
internal class BeansDslApplicationContextInitializer : ApplicationContextInitializer<GenericApplicationContext> {
    override fun initialize(applicationContext: GenericApplicationContext) {
        beans(Clock.systemDefaultZone()).initializer().initialize(applicationContext)
    }
}
