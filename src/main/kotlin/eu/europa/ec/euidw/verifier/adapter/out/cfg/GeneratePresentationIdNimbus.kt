package eu.europa.ec.euidw.verifier.adapter.out.cfg

import com.nimbusds.oauth2.sdk.id.Identifier
import eu.europa.ec.euidw.verifier.application.port.out.cfg.GeneratePresentationId
import eu.europa.ec.euidw.verifier.domain.PresentationId

class GeneratePresentationIdNimbus(private val byteLength: Int) : GeneratePresentationId {

    init {
        require(byteLength>=32){"Value should be greater or equal to 32"}
    }
    override suspend fun invoke(): PresentationId = PresentationId(Identifier(byteLength).value)
}