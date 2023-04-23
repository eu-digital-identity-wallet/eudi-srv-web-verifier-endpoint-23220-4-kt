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

class InitTransactionTest {

    private val testPresentationId = TestContext.testPresentationId

    @Test
    fun `when request option is embed by value, request should be present and presentation should be RequestObjectRetrieved`() =
        runBlocking {
            val verifierConfig = VerifierConfig(
                requestJarOption = EmbedOption.ByValue,
                presentationDefinitionEmbedOption = EmbedOption.ByValue,
                responseUriBuilder = { _ -> URL("https://foo") }
            )

            val input = InitTransactionTO(
                PresentationTypeTO.IdTokenRequest,
                IdTokenTypeTO.SubjectSigned,
                null
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
                responseUriBuilder = { _ -> URL("https://foo") }
            )

            val input = InitTransactionTO(
                PresentationTypeTO.IdTokenRequest,
                IdTokenTypeTO.SubjectSigned,
                null
            )

            val useCase = TestContext.initTransaction(verifierConfig)

            val jwtSecuredAuthorizationRequest = useCase(input).getOrThrow()
            Assertions.assertEquals(jwtSecuredAuthorizationRequest.clientId, verifierConfig.clientId)
            Assertions.assertEquals(uri, jwtSecuredAuthorizationRequest.requestUri)
            Assertions.assertTrue(
                loadPresentationById(testPresentationId)?.let { it is Presentation.Requested } ?: false
            )
        }

    @Test
    fun `when input misses presentation definition validation error is raised`() = runBlocking {

        // Input is invalid.
        //  Misses presentation definition
        val input = InitTransactionTO(
            PresentationTypeTO.VpTokenRequest,
            null,
            null
        )
        testWithInvalidInput(input, ValidationError.MissingPresentationDefinition)
    }

//    @Test
//    fun `when input has invalid presentation definition validation error is raised`() {
//
//        // Input is invalid.
//        //  Invalid presentation definition
//        val input = InitTransactionTO(
//            PresentationTypeTO.VpTokenRequest,
//            null,
//            "invalid presentation definition json"
//        )
//        testWithInvalidInput(input, ValidationError.InvalidPresentationDefinition)
//    }

    private fun testWithInvalidInput(input: InitTransactionTO, expectedError: ValidationError) = input.toDomain().fold(
        onSuccess = { fail { "Invalid input accepted" } },
        onFailure = { throwable ->
            if (throwable is ValidationException) Assertions.assertEquals(expectedError, throwable.error)
            else fail(throwable)
        })

    private suspend fun loadPresentationById(id: PresentationId) =
        TestContext.loadPresentationById(id)
}