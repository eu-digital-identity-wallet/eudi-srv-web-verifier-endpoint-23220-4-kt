package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.verifier.adapter.`in`.web.VerifierApi
import eu.europa.ec.euidw.verifier.adapter.`in`.web.WalletApi
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestMethodOrder
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.core.annotation.Order
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.BodyInserters


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(OrderAnnotation::class)
@AutoConfigureWebTestClient(timeout = Integer.MAX_VALUE.toString()) // used for debugging only
@Disabled
internal class WalletResponseDirectPostWithIdTokenTest {

    @Autowired
    private lateinit var client: WebTestClient

    /**
     * Verifier application to Verifier Backend, Initiate transaction
     *
     * As per OpenId4VP draft 18, section 10.5, Figure 3:
     * - (request) Verifier to Verifier Response endpoint, flow "(2) initiate transaction"
     * - (response) Verifier ResponseEndpoint to Verifier, flow "(3) return transaction-id & request-id"
     */
    fun `Verifier to VerifierBackend - sends HTTP POST presentation definition, return requestUri`(): String {

        val presentationDefinitionBody = TestUtils.loadResource("01-presentationDefinition.json")
        println("presentationDefinitionBody=${presentationDefinitionBody}")

        val requestUri = client.post().uri(VerifierApi.initTransactionPath)
            .contentType(MediaType.APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .body(BodyInserters.fromValue(presentationDefinitionBody))
            .exchange()
            .expectStatus().isOk()
            .expectBody().returnResult()
            .responseBodyContent?.let { JSONObject(String(it)).get("request_uri").toString() }
        println("requestUri=${requestUri}")

        Assertions.assertNotNull(requestUri)

        return requestUri!!
    }

    /**
     * Wallet application to Verifier Backend, get presentation definition
     *
     * As per ISO 23220-4, Appendix B:
     * - (request) mDocApp to Internet Web Service, flow "6 HTTPs GET to request_uri"
     * - (response) Internet Web Service to mDocApp, flow "7 JWS Authorisation request object [section B.3.2.1]"
     */
    fun `Wallet to VerifierBackend - sends HTTP GET requestUri to retrieve presentation definition, return presentationId`(requestUri: String): String {

        // update the request_uri to point to the local server
        val relativeRequestUri = requestUri.removePrefix("http://localhost:0")
        println("relative request_uri: $relativeRequestUri")

        // get the presentation definition
        val getResponse = client.get()
            .uri(relativeRequestUri)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isOk()
            .expectBody().returnResult();

        Assertions.assertNotNull(getResponse.responseBodyContent, "responseBodyContent is empty")

        val getResponseString = String(getResponse.responseBodyContent!!)
        Assertions.assertNotNull(getResponseString, "getResponseString is null")

        println("response: $getResponseString")

        val (header, payload) = TestUtils.parseJWT(getResponseString)
        // debug
        val prettyHeader = TestUtils.prettyPrintJson(header)
        val prettyPayload = TestUtils.prettyPrintJson(payload)
        println("prettyHeader:\n${prettyHeader}")
        println("prettyPayload:\n${prettyPayload}")

        // extract presentationId from payload
        val payloadObject = JSONObject(payload)
        val presentationId = payloadObject.get("nonce").toString()
        println("presentationId: $presentationId")

        Assertions.assertNotNull(presentationId)

        return presentationId
    }

    /**
     * Wallet application to Verifier Backend, submit wallet response
     *
     * As per OpenId4VP draft 18, section 10.5, Figure 3:
     * - (request) Wallet to Verifier Response endpoint, flow "(5) Authorisation Response (VP Token, state)"
     * - (response) Verifier ResponseEndpoint to Wallet, flow "(6) Response (redirect_uri with response_code)"
     *
     * As per ISO 23220-4, Appendix B:
     * - (request) mDocApp to Internet Web Service, flow "12 HTTPs POST to response_uri [section B.3.2.2]
     * - (response) Internet Web Service to mDocApp, flow "14 OK: HTTP 200 with redirect_uri"
     */
    fun `Wallet to VerifierBackend - sends HTTP POST to submit wallet response`(requestId: String) {

        val formEncodedBody: MultiValueMap<String, Any> = LinkedMultiValueMap()
        formEncodedBody.add("state", requestId)
        formEncodedBody.add("idToken", "value 1")

        client.post().uri(WalletApi.walletResponsePath)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            //.accept(MediaType.APPLICATION_JSON)
            .body(BodyInserters.fromValue(formEncodedBody))
            .exchange()
            // then
            .expectStatus().isOk()

    }

    /**
     * Verifier application to Verifier Backend, get authorisation response
     *
     * As per OpenId4VP draft 18, section 10.5, Figure 3:
     * - (request) Verifier to Verifier Response endpoint, flow "(8) fetch response data (transaction-id, response_code)"
     * - (response) Verifier ResponseEndpoint to Verifier, flow "(9) response data (VP Token, Presentation Submission)"
     *
     * As per ISO 23220-4, Appendix B:
     * - (request) mdocVerification application Internet frontend to Internet Web Service, flow "18 HTTPs POST to response_uri [section B.3.2.2]
     * - (response) Internet Web Service to mdocVerification application Internet frontend, flow "20 return status and conditionally return data"
     */
    fun `Verifier Application to Verifier Backend, get authorisation response`(presentationId: String): String {

        val walletResponseUri = VerifierApi.walletResponsePath.replace("{presentationId}", presentationId)

        // when
        val responseSpec = client.get().uri(walletResponseUri)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
        val returnResult = responseSpec.expectBody().returnResult()
        returnResult.status.also { println("response status: ${it}") }
        returnResult.responseHeaders.also { println("response headers: ${it}") }
        returnResult.responseBodyContent?.let {
            println("response body content:\n${TestUtils.prettyPrintJson(String(it))}")
        }

        // then
        Assertions.assertEquals(HttpStatus.OK, returnResult.status)

        return returnResult.responseBodyContent?.let { String(it) }!!
    }

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post presentation definition
     * - wallet to verifier backend, to get presentation definition
     * - wallet to verifier backend, to post wallet response
     */
    @Test @Order(value = 1)
    fun `post wallet response (only idToken) - confirm returns 200`(): Unit = runBlocking {
        // given
        val requestUri = `Verifier to VerifierBackend - sends HTTP POST presentation definition, return requestUri`()
        val requestId = requestUri.removePrefix("http://localhost:0/wallet/request.jwt/")
        val presentationId = `Wallet to VerifierBackend - sends HTTP GET requestUri to retrieve presentation definition, return presentationId`(requestUri)

        // when
        `Wallet to VerifierBackend - sends HTTP POST to submit wallet response`(requestId)

        // then
        Assertions.assertNotNull(presentationId)
    }

    /**
     * Unit test of flow:
     * - verifier to verifier backend, to post presentation definition
     * - wallet to verifier backend, to get presentation definition
     * - wallet to verifier backend, to post wallet response
     * - verifier to verifier backend, to get wallet response
     */
    @Test @Order(value = 2)
    fun `get authorisation response - confirm returns 200`(): Unit = runBlocking {
        // given
        val requestUri = `Verifier to VerifierBackend - sends HTTP POST presentation definition, return requestUri`()
        val requestId = requestUri.removePrefix("http://localhost:0/wallet/request.jwt/")
        val presentationId = `Wallet to VerifierBackend - sends HTTP GET requestUri to retrieve presentation definition, return presentationId`(requestUri)

        `Wallet to VerifierBackend - sends HTTP POST to submit wallet response`(requestId)
        Assertions.assertNotNull(presentationId)

        // when
        val response = `Verifier Application to Verifier Backend, get authorisation response`(presentationId)

        // then
        Assertions.assertNotNull(response, "response is null")
    }

}