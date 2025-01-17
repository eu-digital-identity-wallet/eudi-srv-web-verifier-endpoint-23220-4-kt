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
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApiClient
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import kotlinx.coroutines.test.runTest
import java.net.URL
import java.time.Duration
import kotlin.test.*

class InitTransactionTest {

    private val testTransactionId = TestContext.testTransactionId

    private val uri = URL("https://foo")
    private val verifierConfig = VerifierConfig(
        verifierId = TestContext.verifierId,
        requestJarOption = EmbedOption.ByValue,
        presentationDefinitionEmbedOption = EmbedOption.ByValue,
        responseUriBuilder = { _ -> uri },
        responseModeOption = ResponseModeOption.DirectPostJwt,
        maxAge = Duration.ofDays(3),
        clientMetaData = TestContext.clientMetaData,
    )

    @Test
    fun `when request option is embed by value, request should be present and presentation should be RequestObjectRetrieved`() =
        runTest {
            val input = InitTransactionTO(
                PresentationTypeTO.IdTokenRequest,
                IdTokenTypeTO.SubjectSigned,
                null,
                null,
                "nonce",
            )

            val useCase: InitTransaction = TestContext.initTransaction(
                verifierConfig,
                EmbedOption.byReference { _ -> uri },
                EmbedOption.byReference { _ -> uri },
            )

            val jwtSecuredAuthorizationRequest = useCase(input).getOrElse { fail("Unexpected $it") }
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertNotNull(jwtSecuredAuthorizationRequest.request)
            assertTrue {
                loadPresentationById(testTransactionId)?.let { it is Presentation.RequestObjectRetrieved } ?: false
            }
        }

    @Test
    fun `when request option is embed by ref, request_uri should be present and presentation should be Requested`() =
        runTest {
            val uri = URL("https://foo")
            val verifierConfig = VerifierConfig(
                verifierId = TestContext.verifierId,
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
                null,
                "nonce",
            )

            val useCase = TestContext.initTransaction(
                verifierConfig,
                EmbedOption.byReference { _ -> uri },
                EmbedOption.byReference { _ -> uri },
            )

            val jwtSecuredAuthorizationRequest = useCase(input).getOrElse { fail("Unexpected $it") }
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertEquals(uri.toExternalForm(), jwtSecuredAuthorizationRequest.requestUri)
            assertTrue {
                loadPresentationById(testTransactionId)?.let { it is Presentation.Requested } ?: false
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
        testWithInvalidInput(input, ValidationError.MissingPresentationQuery)
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

            val jwtSecuredAuthorizationRequest = useCase(input).getOrElse { fail("Unexpected $it") }
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertNotNull(jwtSecuredAuthorizationRequest.request)
            val presentation = loadPresentationById(testTransactionId)
            val requestObjectRetrieved = assertIs<Presentation.RequestObjectRetrieved>(presentation)
            assertEquals(ResponseModeOption.DirectPost, requestObjectRetrieved.responseMode)
        }

    /**
     * Verifies [InitTransactionTO.jarMode] takes precedence over [VerifierConfig.requestJarOption].
     */
    @Test
    fun `when jar_mode is provided this must take precedence over what is configured in VerifierConfig`() =
        runTest {
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
            val jwtSecuredAuthorizationRequest = useCase(input).getOrElse { fail("Unexpected $it") }
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertNull(jwtSecuredAuthorizationRequest.request)
            assertNotNull(jwtSecuredAuthorizationRequest.requestUri)
            val presentation = loadPresentationById(testTransactionId)
            assertIs<Presentation.Requested>(presentation)
            Unit
        }

    /**
     * Verifies [InitTransactionTO.presentationDefinitionMode] takes precedence over [VerifierConfig.presentationDefinitionEmbedOption].
     */
    @Test
    fun `when presentation_definition_mode is provided this must take precedence over what is configured in VerifierConfig`() =
        runTest {
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
            val jwtSecuredAuthorizationRequest = useCase(input).getOrElse { fail("Unexpected $it") }
            assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.verifierId.clientId)
            assertNotNull(jwtSecuredAuthorizationRequest.request)
            val claims = SignedJWT.parse(jwtSecuredAuthorizationRequest.request).payload!!.toJSONObject()!!
            assertEquals(uri.toExternalForm(), claims["presentation_definition_uri"])
            val presentation = loadPresentationById(testTransactionId)
            assertIs<Presentation.RequestObjectRetrieved>(presentation)
            Unit
        }

    @Test
    fun `when wallet_response_redirect_uri_template is invalid, validation error InvalidWalletResponseTemplate should be raised`() =
        runTest {
            val useCase: InitTransaction = TestContext.initTransaction(
                verifierConfig,
                EmbedOption.byReference { _ -> uri },
                EmbedOption.byReference { _ -> uri },
            )

            val invalidPlaceHolderInput = InitTransactionTO(
                PresentationTypeTO.IdTokenRequest,
                IdTokenTypeTO.SubjectSigned,
                null,
                null,
                "nonce",
                redirectUriTemplate = "https://client.example.org/cb#response_code=#CODE#",
            )

            useCase(invalidPlaceHolderInput)
                .onLeft {
                    assertTrue(
                        "Should fail with ValidationError.InvalidWalletResponseTemplate",
                    ) { it == ValidationError.InvalidWalletResponseTemplate }
                }
                .onRight {
                    fail("Should fail with ValidationError.InvalidWalletResponseTemplate")
                }

            val invalidUrlInput = InitTransactionTO(
                PresentationTypeTO.IdTokenRequest,
                IdTokenTypeTO.SubjectSigned,
                null,
                null,
                "nonce",
                redirectUriTemplate =
                    "hts:/client.example.org/cb%response_code=${CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER}",
            )

            useCase(invalidUrlInput)
                .onLeft {
                    assertTrue(
                        "Should fail with ValidationError.InvalidWalletResponseTemplate",
                    ) { it == ValidationError.InvalidWalletResponseTemplate }
                }
                .onRight {
                    fail("Should fail with ValidationError.InvalidWalletResponseTemplate")
                }
        }

    @Test
    fun `when wallet_response_redirect_uri_template is valid, then get wallet response method should be REDIRECT`() =
        runTest {
            val input = InitTransactionTO(
                PresentationTypeTO.IdTokenRequest,
                IdTokenTypeTO.SubjectSigned,
                null,
                null,
                "nonce",
                redirectUriTemplate =
                    "https://client.example.org/cb#response_code=${CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER}",
            )

            val useCase: InitTransaction = TestContext.initTransaction(
                verifierConfig,
                EmbedOption.byReference { _ -> uri },
                EmbedOption.byReference { _ -> uri },
            )

            useCase(input).getOrElse { fail("Unexpected $it") }
            val presentation = loadPresentationById(testTransactionId)
            assertIs<Presentation.RequestObjectRetrieved>(presentation)
            assertIs<GetWalletResponseMethod.Redirect>(presentation.getWalletResponseMethod)
        }

    @Test
    fun `when wallet_response_redirect_uri_template is not passed, then get wallet response method should be POLL`() =
        runTest {
            val input = InitTransactionTO(
                PresentationTypeTO.IdTokenRequest,
                IdTokenTypeTO.SubjectSigned,
                null,
                null,
                "nonce",
            )

            val useCase: InitTransaction = TestContext.initTransaction(
                verifierConfig,
                EmbedOption.byReference { _ -> uri },
                EmbedOption.byReference { _ -> uri },
            )

            useCase(input).getOrElse { fail("Unexpected $it") }
            val presentation = loadPresentationById(testTransactionId)
            assertIs<Presentation.RequestObjectRetrieved>(presentation)
            assertIs<GetWalletResponseMethod.Poll>(presentation.getWalletResponseMethod)
        }

    private fun testWithInvalidInput(input: InitTransactionTO, expectedError: ValidationError) =
        input.toDomain().fold(
            ifRight = { fail("Invalid input accepted") },
            ifLeft = { error -> assertEquals(expectedError, error) },
        )

    private suspend fun loadPresentationById(id: TransactionId) =
        TestContext.loadPresentationById(id)
}
