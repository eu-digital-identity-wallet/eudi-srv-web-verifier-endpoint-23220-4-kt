package eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.serializer

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.listSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import java.security.cert.X509Certificate

object X509CertificateNonEmptyListSerializer : KSerializer<NonEmptyList<X509Certificate>?> {
    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("NonEmptyList<X509Certificate>") {
            element("list", listSerialDescriptor(X509CertificateSerializer.descriptor))
        }

    override fun serialize(encoder: Encoder, value: NonEmptyList<X509Certificate>?) {
        val list = value?.toList() ?: listOf()
        encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, ListSerializer(X509CertificateSerializer), list)
        }
    }

    override fun deserialize(decoder: Decoder): NonEmptyList<X509Certificate>? {
        val list = decoder.decodeStructure(descriptor) {
            var listValue: List<X509Certificate>? = null
            while (true) {
                when (val index = decodeElementIndex(descriptor)) {
                    0 -> listValue = decodeSerializableElement(descriptor, 0, ListSerializer(X509CertificateSerializer))
                    CompositeDecoder.DECODE_DONE -> break
                    else -> error("Unexpected index: $index")
                }
            }
            listValue ?: error("Missing list value")
        }
        return list.toNonEmptyListOrNull()
    }
}
