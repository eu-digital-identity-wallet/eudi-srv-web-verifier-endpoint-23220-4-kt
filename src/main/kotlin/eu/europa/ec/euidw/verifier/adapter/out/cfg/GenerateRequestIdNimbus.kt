package eu.europa.ec.euidw.verifier.adapter.out.cfg

import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.euidw.verifier.application.port.out.cfg.GenerateRequestId
import eu.europa.ec.euidw.verifier.domain.RequestId

class GenerateRequestIdNimbus(private val byteLength: Int) : GenerateRequestId {
    init {
        require(byteLength>=32){"Value should be greater or equal to 32"}
    }
    override suspend fun invoke(): RequestId = RequestId(State(byteLength).value)
}