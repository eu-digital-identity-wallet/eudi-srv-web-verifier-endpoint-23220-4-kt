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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.qrcode

import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.GenerateQrCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.PNGImage
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.Pixels
import qrcode.QRCode
import qrcode.color.Colors
import qrcode.raw.ErrorCorrectionLevel

object GenerateQrCodeFromData : GenerateQrCode {
    override suspend operator fun invoke(data: String, size: Pixels): Result<PNGImage> {
        return kotlin.runCatching {
            QRCode
                .ofSquares()
                .withColor(Colors.BLACK)
                .withErrorCorrectionLevel(ErrorCorrectionLevel.LOW)
                .build(data)
                .renderToBytes()
        }
    }
}
