package eu.europa.ec.eudi.verifier.endpoint.`in`

import eu.europa.ec.eudi.verifier.endpoint.adapter.`in`.web.WalletApi
import org.junit.jupiter.api.Assertions
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.BodyInserters

object WalletApiClient {

    /**
     * Wallet application to Verifier Backend, get presentation definition
     *
     * As per ISO 23220-4, Appendix B:
     * - (request) mDocApp to Internet Web Service, flow "6 HTTPs GET to request_uri"
     * - (response) Internet Web Service to mDocApp, flow "7 JWS Authorisation request object [section B.3.2.1]"
     */
    fun getRequestObject(client: WebTestClient, requestUri: String) {

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
    fun directPost(client: WebTestClient, formEncodedBody: MultiValueMap<String, Any>) {


        client.post().uri(WalletApi.walletResponsePath)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .accept(MediaType.APPLICATION_JSON)
            .body(BodyInserters.fromValue(formEncodedBody))
            .exchange()
            // then
            .expectStatus().isOk()

    }
}