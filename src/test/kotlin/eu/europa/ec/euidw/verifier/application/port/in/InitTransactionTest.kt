@file:Suppress("invisible_reference", "invisible_member")

package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.verifier.TestContext
import eu.europa.ec.euidw.verifier.domain.EmbedOption
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.PresentationId
import eu.europa.ec.euidw.verifier.domain.VerifierConfig
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.net.URL
import java.time.Duration

class InitTransactionTest {

    private val testPresentationId = TestContext.testPresentationId

    @Test
    fun `when request option is embed by value, request should be present and presentation should be RequestObjectRetrieved`() =
        runBlocking {
            val verifierConfig = VerifierConfig(
                requestJarOption = EmbedOption.ByValue,
                presentationDefinitionEmbedOption = EmbedOption.ByValue,
                responseUriBuilder = { _ -> URL("https://foo") },
                maxAge = Duration.ofDays(3),
                clientMetaData = TestContext.clientMetaData
            )

            val input = InitTransactionTO(
                PresentationTypeTO.IdTokenRequest,
                IdTokenTypeTO.SubjectSigned,
                null,
                "nonce"
            )

            val useCase: InitTransaction = TestContext.initTransaction(verifierConfig)

            val jwtSecuredAuthorizationRequest = useCase(input).getOrThrow()
            Assertions.assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.clientId)
            Assertions.assertNotNull(jwtSecuredAuthorizationRequest.request)
            Assertions.assertTrue(
                loadPresentationById(testPresentationId)?.let { it is Presentation.RequestObjectRetrieved } ?: false)
        }

    @Test
    fun `when request option is embed by ref, request_uri should be present and presentation should be Requested`() =
        runBlocking {
            val uri = URL("https://foo")
            val verifierConfig = VerifierConfig(
                requestJarOption = EmbedOption.ByReference { _ -> uri },
                presentationDefinitionEmbedOption = EmbedOption.ByValue,
                responseUriBuilder = { _ -> URL("https://foo") },
                maxAge = Duration.ofDays(3),
                clientMetaData = TestContext.clientMetaData
            )

            val input = InitTransactionTO(
                PresentationTypeTO.IdTokenRequest,
                IdTokenTypeTO.SubjectSigned,
                null,
                "nonce"
            )

            val useCase = TestContext.initTransaction(verifierConfig)

            val jwtSecuredAuthorizationRequest = useCase(input).getOrThrow()
            Assertions.assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.clientId)
            Assertions.assertEquals(uri.toExternalForm(), jwtSecuredAuthorizationRequest.requestUri)
            Assertions.assertTrue(
                loadPresentationById(testPresentationId)?.let { it is Presentation.Requested } ?: false
            )
        }

    @Test
    fun `when input misses presentation definition validation error is raised`() = runBlocking {

        // Input is invalid.
        //  Misses presentation definition
        val input = InitTransactionTO(
            type = PresentationTypeTO.VpTokenRequest,
            idTokenType = null,
            presentationDefinition = null,
            nonce = "nonce"
        )
        testWithInvalidInput(input, ValidationError.MissingPresentationDefinition)
    }

    @Test
    fun `when input misses nonce validation error is raised`() = runBlocking {

        // Input is invalid.
        //  Misses presentation definition
        val input = InitTransactionTO(
            type = PresentationTypeTO.IdTokenRequest,
            idTokenType = IdTokenTypeTO.SubjectSigned,
            presentationDefinition = null,
            nonce = null
        )
        testWithInvalidInput(input, ValidationError.MissingNonce)
    }

//

    private fun testWithInvalidInput(input: InitTransactionTO, expectedError: ValidationError) = input.toDomain().fold(
        onSuccess = { fail { "Invalid input accepted" } },
        onFailure = { throwable ->
            if (throwable is ValidationException) Assertions.assertEquals(expectedError, throwable.error)
            else fail(throwable)
        })

    private suspend fun loadPresentationById(id: PresentationId) =
        TestContext.loadPresentationById(id)
}