package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.verifier.domain.Nonce
import eu.europa.ec.euidw.verifier.domain.PresentationId
import eu.europa.ec.euidw.verifier.domain.RequestId
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestMethodOrder
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.core.annotation.Order
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(OrderAnnotation::class)
@AutoConfigureWebTestClient(timeout = Integer.MAX_VALUE.toString()) // used for debugging only
internal class WalletResponseDirectPostWithIdTokenTest {

    @Autowired
    private lateinit var client: WebTestClient


    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post presentation definition
     * - wallet to verifier backend, to get presentation definition
     * - wallet to verifier backend, to post wallet response
     */
    @Test
    @Order(value = 1)
    fun `post wallet response (only idToken) - confirm returns 200`(): Unit = runBlocking {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("01-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri?.removePrefix("http://localhost:0/wallet/request.jwt/")!!)
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")

        // when
        WalletApiClient.directPost(client, formEncodedBody)


    }

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post presentation definition
     * - wallet to verifier backend, to get presentation definition
     * - wallet to verifier backend, to post wallet response
     * - verifier to verifier backend, to get wallet response
     */
    @Test
    @Order(value = 2)
    fun `get authorisation response - confirm returns 200`(): Unit = runBlocking {
        // given
        val initTransaction = VerifierApiClient.loadInitTransactionTO("01-presentationDefinition.json")
        val transactionInitialized = VerifierApiClient.initTransaction(client, initTransaction)
        val requestId =
            RequestId(transactionInitialized.requestUri!!.removePrefix("http://localhost:0/wallet/request.jwt/"))
        WalletApiClient.getRequestObject(client, transactionInitialized.requestUri!!)

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId.value)
        formEncodedBody.add("id_token", "value 1")

        WalletApiClient.directPost(client, formEncodedBody)

        // when
        val response = VerifierApiClient.getWalletResponse(
            client,
            PresentationId(transactionInitialized.presentationId),
            Nonce(initTransaction.nonce!!)
        )

        // then
        Assertions.assertNotNull(response, "response is null")
    }

}