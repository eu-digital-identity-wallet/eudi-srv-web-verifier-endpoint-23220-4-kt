package eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.serializer

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.io.encoding.Base64


object X509CertificateSerializer : KSerializer<X509Certificate> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("X509Certificate", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: X509Certificate) {
        val encoded = Base64.encode(value.encoded)
        encoder.encodeString(encoded)
    }

    override fun deserialize(decoder: Decoder): X509Certificate {
        val encoded = decoder.decodeString()
        val decoded = Base64.decode(encoded)
        return CertificateFactory.getInstance("X.509").generateCertificate(decoded.inputStream()) as X509Certificate
    }
}
