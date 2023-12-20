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
@file:Suppress("invisible_reference", "invisible_member")

package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.getOrElse
import arrow.core.raise.either
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApiClient
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import kotlinx.coroutines.test.runTest
import java.net.URL
import java.time.Duration
import kotlin.test.*

class InitTransactionTest {

    private val testPresentationId = TestContext.testPresentationId

    @Test
    fun `when request option is embed by value, request should be present and presentation should be RequestObjectRetrieved`() =
        runTest {
            val uri = URL("https://foo")
            val verifierConfig = VerifierConfig(
                clientIdScheme = TestContext.clientIdScheme,
                requestJarOption = EmbedOption.ByValue,
                presentationDefinitionEmbedOption = EmbedOption.ByValue,
                responseUriBuilder = { _ -> uri },
                responseModeOption = ResponseModeOption.DirectPostJwt,
                maxAge = Duration.ofDays(3),
                clientMetaData = TestContext.clientMetaData,
            )

            val input = InitTransactionTO(
                PresentationTypeTO.IdTokenRequest,
                IdTokenTypeTO.SubjectSigned,
                null,
                "nonce",
            )

            val useCase: InitTransaction = TestContext.initTransaction(
                verifierConfig,
                EmbedOption.byReference { _ -> uri },
                EmbedOption.byReference { _ -> uri },
            )

            val jwtSecuredAuthorizationRequest = either { useCase(input) }.getOrElse { fail("Unexpected $it") }
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.clientIdScheme.clientId)
            assertNotNull(jwtSecuredAuthorizationRequest.request)
            assertTrue {
                loadPresentationById(testPresentationId)?.let { it is Presentation.RequestObjectRetrieved } ?: false
            }
        }

    @Test
    fun `when request option is embed by ref, request_uri should be present and presentation should be Requested`() =
        runTest {
            val uri = URL("https://foo")
            val verifierConfig = VerifierConfig(
                clientIdScheme = TestContext.clientIdScheme,
                requestJarOption = EmbedOption.ByReference { _ -> uri },
                presentationDefinitionEmbedOption = EmbedOption.ByValue,
                responseUriBuilder = { _ -> URL("https://foo") },
                responseModeOption = ResponseModeOption.DirectPostJwt,
                maxAge = Duration.ofDays(3),
                clientMetaData = TestContext.clientMetaData,
            )

            val input = InitTransactionTO(
                PresentationTypeTO.IdTokenRequest,
                IdTokenTypeTO.SubjectSigned,
                null,
                "nonce",
            )

            val useCase = TestContext.initTransaction(
                verifierConfig,
                EmbedOption.byReference { _ -> uri },
                EmbedOption.byReference { _ -> uri },
            )

            val jwtSecuredAuthorizationRequest = either { useCase(input) }.getOrElse { fail("Unexpected $it") }
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.clientIdScheme.clientId)
            assertEquals(uri.toExternalForm(), jwtSecuredAuthorizationRequest.requestUri)
            assertTrue {
                loadPresentationById(testPresentationId)?.let { it is Presentation.Requested } ?: false
            }
        }

    @Test
    fun `when input misses presentation definition validation error is raised`() = runTest {
        // Input is invalid.
        //  Misses presentation definition
        val input = InitTransactionTO(
            type = PresentationTypeTO.VpTokenRequest,
            idTokenType = null,
            presentationDefinition = null,
            nonce = "nonce",
        )
        testWithInvalidInput(input, ValidationError.MissingPresentationDefinition)
    }

    @Test
    fun `when input misses nonce validation error is raised`() = runTest {
        // Input is invalid.
        //  Misses presentation definition
        val input = InitTransactionTO(
            type = PresentationTypeTO.IdTokenRequest,
            idTokenType = IdTokenTypeTO.SubjectSigned,
            presentationDefinition = null,
            nonce = null,
        )
        testWithInvalidInput(input, ValidationError.MissingNonce)
    }

    /**
     * Verifies [InitTransactionTO.responseMode] takes precedence over [VerifierConfig.responseModeOption].
     */
    @Test
    fun `when response_mode is provided this must take precedence over what is configured in VerifierConfig`() =
        runTest {
            val uri = URL("https://foo")
            val verifierConfig = VerifierConfig(
                clientIdScheme = TestContext.clientIdScheme,
                requestJarOption = EmbedOption.ByValue,
                presentationDefinitionEmbedOption = EmbedOption.ByValue,
                responseUriBuilder = { _ -> uri },
                responseModeOption = ResponseModeOption.DirectPostJwt,
                maxAge = Duration.ofDays(3),
                clientMetaData = TestContext.clientMetaData,
            )

            val input = InitTransactionTO(
                type = PresentationTypeTO.IdTokenRequest,
                idTokenType = IdTokenTypeTO.SubjectSigned,
                nonce = "nonce",
                responseMode = ResponseModeTO.DirectPost,
            )

            val useCase: InitTransaction = TestContext.initTransaction(
                verifierConfig,
                EmbedOption.byReference { _ -> uri },
                EmbedOption.byReference { _ -> uri },
            )

            val jwtSecuredAuthorizationRequest = either { useCase(input) }.getOrElse { fail("Unexpected $it") }
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.clientIdScheme.clientId)
            assertNotNull(jwtSecuredAuthorizationRequest.request)
            val presentation = loadPresentationById(testPresentationId)
            val requestObjectRetrieved = assertIs<Presentation.RequestObjectRetrieved>(presentation)
            assertEquals(ResponseModeOption.DirectPost, requestObjectRetrieved.responseMode)
        }

    /**
     * Verifies [InitTransactionTO.jarMode] takes precedence over [VerifierConfig.requestJarOption].
     */
    @Test
    fun `when jar_mode is provided this must take precedence over what is configured in VerifierConfig`() =
        runTest {
            val uri = URL("https://foo")
            val verifierConfig = VerifierConfig(
                clientIdScheme = TestContext.clientIdScheme,
                requestJarOption = EmbedOption.ByValue,
                presentationDefinitionEmbedOption = EmbedOption.ByValue,
                responseUriBuilder = { _ -> uri },
                responseModeOption = ResponseModeOption.DirectPostJwt,
                maxAge = Duration.ofDays(3),
                clientMetaData = TestContext.clientMetaData,
            )

            val input = InitTransactionTO(
                type = PresentationTypeTO.IdTokenRequest,
                idTokenType = IdTokenTypeTO.SubjectSigned,
                nonce = "nonce",
                jarMode = EmbedModeTO.ByReference,
            )

            val useCase: InitTransaction = TestContext.initTransaction(
                verifierConfig,
                EmbedOption.byReference { _ -> uri },
                EmbedOption.byReference { _ -> uri },
            )

            // we expect the Authorization Request to contain a request_uri
            // and the Presentation to be in state Requested
            val jwtSecuredAuthorizationRequest = either { useCase(input) }.getOrElse { fail("Unexpected $it") }
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.clientIdScheme.clientId)
            assertNull(jwtSecuredAuthorizationRequest.request)
            assertNotNull(jwtSecuredAuthorizationRequest.requestUri)
            val presentation = loadPresentationById(testPresentationId)
            assertIs<Presentation.Requested>(presentation)
            Unit
        }

    /**
     * Verifies [InitTransactionTO.presentationDefinitionMode] takes precedence over [VerifierConfig.presentationDefinitionEmbedOption].
     */
    @Test
    fun `when presentation_definition_mode is provided this must take precedence over what is configured in VerifierConfig`() =
        runTest {
            val uri = URL("https://foo")
            val verifierConfig = VerifierConfig(
                clientIdScheme = TestContext.clientIdScheme,
                requestJarOption = EmbedOption.ByValue,
                presentationDefinitionEmbedOption = EmbedOption.ByValue,
                responseUriBuilder = { _ -> uri },
                responseModeOption = ResponseModeOption.DirectPostJwt,
                maxAge = Duration.ofDays(3),
                clientMetaData = TestContext.clientMetaData,
            )

            val input = VerifierApiClient.loadInitTransactionTO(
                "00-presentationDefinition.json",
            ).copy(presentationDefinitionMode = EmbedModeTO.ByReference)

            val useCase: InitTransaction = TestContext.initTransaction(
                verifierConfig,
                EmbedOption.byReference { _ -> uri },
                EmbedOption.byReference { _ -> uri },
            )

            // we expect the Authorization Request to contain a request that contains a presentation_definition_uri
            // and the Presentation to be in state RequestedObjectRetrieved
            val jwtSecuredAuthorizationRequest = either { useCase(input) }.getOrElse { fail("Unexpected $it") }
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.clientIdScheme.clientId)
            assertNotNull(jwtSecuredAuthorizationRequest.request)
            val claims = SignedJWT.parse(jwtSecuredAuthorizationRequest.request).payload!!.toJSONObject()!!
            assertEquals(uri.toExternalForm(), claims["presentation_definition_uri"])
            val presentation = loadPresentationById(testPresentationId)
            assertIs<Presentation.RequestObjectRetrieved>(presentation)
            Unit
        }

//

    private fun testWithInvalidInput(input: InitTransactionTO, expectedError: ValidationError) =
        either { input.toDomain() }.fold(
            ifRight = { fail("Invalid input accepted") },
            ifLeft = { error -> assertEquals(expectedError, error) },
        )

    private suspend fun loadPresentationById(id: PresentationId) =
        TestContext.loadPresentationById(id)
}
