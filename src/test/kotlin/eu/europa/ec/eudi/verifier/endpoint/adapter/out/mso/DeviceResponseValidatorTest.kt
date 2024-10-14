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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso

import arrow.core.nel
import arrow.core.nonEmptyListOf
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import org.springframework.core.io.ClassPathResource
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Clock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

object Data {

    /**
     * Contains three documents,
     * The first and the second are valid
     * The 3d has expired validity info
     */
    val ThreeDocumentVP =
        """
        o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHODo2dkb2NUeXBld2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xbGlzc3VlclNpZ25lZKJqbmFtZVNwYWNlc6F3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjGD2BhYZKRmcmFuZG9tWCB5VtAPjr0U59_EMVF-PaP_tV_2ZsIaXyF6PMytTrIXIGhkaWdlc3RJRAFsZWxlbWVudFZhbHVlZGFnYWxxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWXYGFhkpGZyYW5kb21YIJxOCMP3T_ANTSVKWFeSWAZ-nGW8zGEMrRJ9jz5c1k4EaGRpZ2VzdElEBmxlbGVtZW50VmFsdWVleGVuaWFxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWGykZnJhbmRvbVgghdsUuUPWliUu5eDkczAuikDbp7c4sC_U_EM9QwhituZoZGlnZXN0SUQAbGVsZW1lbnRWYWx1ZdkD7GoyMDI0LTEwLTAycWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVqaXNzdWVyQXV0aIRDoQEmoRghWQLoMIIC5DCCAmqgAwIBAgIUcjJt9mMImntQD4w_JqaFy8LC0sowCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTIzMDkwMjE3NDI1MVoXDTI0MTEyNTE3NDI1MFowVDEWMBQGA1UEAwwNUElEIERTIC0gMDAwMTEtMCsGA1UECgwkRVVESSBXYWxsZXQgUmVmZXJlbmNlIEltcGxlbWVudGF0aW9uMQswCQYDVQQGEwJVVDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEkEfNQcLRumao61kGFlsOaT3hsc5a96bVyK937SPd6yfyrwvUwIKiU2pCQI9p1eMkBiyZdLcPj4cH2xw6yGLFijggEQMIIBDDAfBgNVHSMEGDAWgBSzbLiRFxzXpBpmMYdC4YvAQMyVGzAWBgNVHSUBAf8EDDAKBggrgQICAAABAjBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX1VUXzAxLmNybDAdBgNVHQ4EFgQUge_0nFyDClCmRr73UHhaUz4_2JswDgYDVR0PAQH_BAQDAgeAMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwIDaAAwZQIwRfraou8tlVPrtIhE2GQa0CqeOo5KK3fa4vQeeV8vLZCbA_KBCZRrTi2Sg61_waGFAjEAm55O7VAQn18OtwAsz5iz_uQRQH5l7jD7AQS-1nOC6oPeH1zEiOYQF2QBMidDQE0KWQJZ2BhZAlSmZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFndmVyc2lvbmMxLjBsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMDJUMDc6MTg6MjlaaXZhbGlkRnJvbcB0MjAyNC0xMC0wMlQwNzoxODoyOVpqdmFsaWRVbnRpbMB0MjAyNC0xMi0zMVQwMDowMDowMFpsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMagAWCD1tmkC_SS1W_5QHIxS0lfZXF4AJgC9x5MHRS-ZNXtPQwFYILVy_RUhsocrlvYaPUaV6qpCvnZWbRhd29OJWypeFFqHAlggEQ4yzKb0AykEzTI0ILDdvufaIoJICu9Lyt2kiQTvgPwDWCDmxP2TCqzsG6Z-cHWqrAomNzK4bLmY_spv7evKDqRnpQRYIN4ZOEitfPatTuVwRqv60ghoWJDhRo505El_rbNhwhcRBVggqiSqO4DD4TDgMX1-2TPzxS0TvcpqCB-TXl8X-Vc53a8GWCBylhFs3aWr7Z17TPGhNrARESUpyK0hH2a_JOIw083LPAdYIBkAWPU5KmV9qqz-1P4wxJf2O15POu8k7XS0I43XXkWabWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVgg-yPkiiRw3rW3jbEKydxKJwuBC3AoDrg_ynyAr3xwm4UiWCDvJPL3WoZVyTf12wNKTE3qvmhm_6sr2cv5w-V-FZcsO29kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhALWZqhlP3pULX5h0a2Fs92HddabQNjni4dycLB3FuURl7tnMcjeEoU6YlYPsSB5I3EISU8X1z_wiifHfS1qfIImxkZXZpY2VTaWduZWSiam5hbWVTcGFjZXPYGEGgamRldmljZUF1dGihb2RldmljZVNpZ25hdHVyZYRDoQEmoPZYQNYU6xTtzL99Vt_f88mwMkNRZJ_Jy4RUJ0nDVIjLUNsM6zcDCDdK2Hlv6ORppOY4UOCnXZRR4Dzo9Z6KdBVDQ5CjZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFsaXNzdWVyU2lnbmVkompuYW1lU3BhY2VzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMYPYGFhqpGZyYW5kb21YINAgNZtcuSe_yfuBEYGNZy8bVbi5zbveyroOb7zVrG8FaGRpZ2VzdElEAWxlbGVtZW50VmFsdWVqYWdhbGxpYWRvdXFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWGSkZnJhbmRvbVggdQ_4OFw7MQUrcqGFsqYYC3Eq8q-m1dbyHSog4XAy8AVoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZWVyYW5pYXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l2BhYbKRmcmFuZG9tWCCHwoMMz1entxEMmpZNMUFQrSrxfpVUHQO7iRu_MYHo9mhkaWdlc3RJRAJsZWxlbWVudFZhbHVl2QPsajIwMjItMDctMTlxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZWppc3N1ZXJBdXRohEOhASahGCFZAugwggLkMIICaqADAgECAhRyMm32Ywiae1APjD8mpoXLwsLSyjAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjMwOTAyMTc0MjUxWhcNMjQxMTI1MTc0MjUwWjBUMRYwFAYDVQQDDA1QSUQgRFMgLSAwMDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESQR81BwtG6ZqjrWQYWWw5pPeGxzlr3ptXIr3ftI93rJ_KvC9TAgqJTakJAj2nV4yQGLJl0tw-PhwfbHDrIYsWKOCARAwggEMMB8GA1UdIwQYMBaAFLNsuJEXHNekGmYxh0Lhi8BAzJUbMBYGA1UdJQEB_wQMMAoGCCuBAgIAAAECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcuZGV2L2NybC9waWRfQ0FfVVRfMDEuY3JsMB0GA1UdDgQWBBSB7_ScXIMKUKZGvvdQeFpTPj_YmzAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1hbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNoADBlAjBF-tqi7y2VU-u0iETYZBrQKp46jkord9ri9B55Xy8tkJsD8oEJlGtOLZKDrX_BoYUCMQCbnk7tUBCfXw63ACzPmLP-5BFAfmXuMPsBBL7Wc4Lqg94fXMSI5hAXZAEyJ0NATQpZAlnYGFkCVKZnZG9jVHlwZXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMWd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB0MjAyNC0xMC0wMlQxMDowNTozN1ppdmFsaWRGcm9twHQyMDI0LTEwLTAyVDEwOjA1OjM3Wmp2YWxpZFVudGlswHQyMDI0LTEyLTMxVDAwOjAwOjAwWmx2YWx1ZURpZ2VzdHOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xqABYICcw9wXXD_hU4ad0AP7IDjPJ_45_xeQigPsxgIVrh1s9AVggiBIL1rgeZFtNoNSVSAKgmBJ6xX86YQGL5fzcBghwty4CWCB6ASivxtd1b_cfbXMcuPStSNoL2X4SQOc3YaEGcoYFwQNYIEarE29z4TSOoWfuEpft_sMpphp9gs-7wz8kXs4Bh8YdBFggKG-f47ZqCLTORdmFwSP7NeOwuGImbxgYQtHjDD7PfKoFWCA8gWAaqFN_kA62tirSN12ZeGAuB6OkqxTNkJgkTiGtYAZYII3JtbamXAnmXc8J71MUnhjkYrZOQ9VObbhxCu49gbgEB1gg_IMT_qhpqii2wtpYDnT9M_a0kp4SJEG-2ODfzPK7ycJtZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCBifnFnGqtYk52XaJmfPc1CXJbe95f7tdf8k8AG7ISwfSJYILyC7he-oFwTlNm7XF1QtCpQ-m1w7AvCc0uTUZedK5PYb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2WED-wcT-udNB7z1RgTCU-hcV1VQCtfwJhGXb-8SQYXsJdXDDPcSURTas6oQgt6MIxZW63zukOocw-IDpLVZ6q0IfbGRldmljZVNpZ25lZKJqbmFtZVNwYWNlc9gYQaBqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhATJ4Nf3oSVoJ39mhFRpnDFJPztg4sAP3oCo3mS72tLg_XwCRCbZt2Hiip8Tvf-oJqnAEd3TEsY-LTLK4JhbeIHaNnZG9jVHlwZXVvcmcuaXNvLjE4MDEzLjUuMS5tRExsaXNzdWVyU2lnbmVkompuYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYXYGFkhNqRmcmFuZG9tWCD5f-qUYfgoblNXU3kTdVgzTk-_hfxk_YAzeCuD7AQGpmhkaWdlc3RJRANsZWxlbWVudFZhbHVlWSDX_9j_4AAQSkZJRgABAQAAAAAAAAD_4QBiRXhpZgAATU0AKgAAAAgABQESAAMAAAABAAEAAAEaAAUAAAABAAAASgEbAAUAAAABAAAAUgEoAAMAAAABAAEAAAITAAMAAAABAAEAAAAAAAAAAAAAAAAAAQAAAAAAAAAB_9sAQwADAgICAgIDAgICAwMDAwQGBAQEBAQIBgYFBgkICgoJCAkJCgwPDAoLDgsJCQ0RDQ4PEBAREAoMEhMSEBMPEBAQ_8AACwgA6gDXAQERAP_EAB4AAQACAgIDAQAAAAAAAAAAAAAHCQgKBQYBAwQC_8QARxAAAQMDAwIEBAMDBwgLAAAAAQIDBAAFBgcIERIhCRMxQRQiUWEjMnEVQoEWFyRSYoKRGDNDY3KhorEZRFNXc5WjwcLR1P_aAAgBAQAAPwC1OlKUpSlKjXXzcPpXtrwV_PtVMgEGIOpuHDZAcmXF8DkMx2uR1rPbuSEpB5WpKeSKftxviw7htXJkyz6YTlabYusrbaRbHObo82ewU7M46m1e48jy-nnjqVxzWH-UZ7nWbv8AxWaZpfr-9zz5l0uL0pXP15cUTXZdP9w2uulcqPK081cyyxfDKCkMRbq8IyuPZbBUWnE_2VJI-1Zk4h40evdl0_k4_lOBYzkeUpbS3ByFalxUA8d1yYjQ6Hlk8n8JTCR2-X64uan7zd0Or896ZmmtWTqZd5HwFvmqgQkp55AEeP0Nnj06lAq49SaiyBluVWqebrbMmu0OaTyZLE1xt3n69aSD_vrIbRPxG91-ik5n4fUmbltoQoF205Q6u4NLT9EurV57XA9AhwJ59QfSrddoG_TSXdvblWy1BeN5tCZ82djc55KnFIA-Z6K5wBIaB7EgJWn95CQUqVkxSlKUpSlKUpSlKVG24XXzBNtell11U1Al9MOEAzDhtqAfuMxYPlRWQfVaulR-iUpWs8JSojXv3FbitR9zepE3UbUW5Fx1wlq329pR-FtkXnlLDCT6AepV6qVypXJNRhSlKUpXK4pleSYNkduy_EL1LtF6tMhMqFNiuFDrDqT2Ukj_AAI9CCQeQavs2Db1LPu206cYvfw8DUHGm22r_AQOlEhJ7ImsD_s1kEKT6tr5SflU2peU9KUpSlKUpSlKUqhrxON0srcFr1MxPH7mpzCMAddtNsbbUC1LmJVxKmdvzdS0-Wg8keW0lSeCtXOHlKUpSlKVI23vXPL9uWrVh1Zwx1SpVpf4lQy6UNXCGrs9FcIB-Vafcg9KglYHUkVsgaeZ7jWqWC2LUXDp3xdlyKAzcYTpHCvLcSCEqH7q090qSe6VAg9xXYqUpSlKUpSlKVj3v013Xt62w5bmdun_AAt-uTIsNhWFhKxPlBSUuI59VNNh18Djv5Na7dKUpSlKUpVv3gt66Kv-n2U7f7zP65eKyf23Zm1rHV8BJVw-2hPr0tyOFk_WX6-gqyqlKUpSlKUpSlVAeNVrGu9aj4bodbZZMTGoCr5ckIXylUyUShlCx7KbZbKh9pNVrUpSlKUpSlZEeH9rEvRPdjgmSSJTjNqu80Y9dgkgJVGmcNBSyf3G3Sy8eO_4Xv6HYgpSlKUpSlKUr8rWhtCnHFBKUglSieAB9TWtPub1Wc1v3AZ5qn55ej369PuQVFJSRBbPlRUkHvyGG2gfuPaoxpSlKUpSlKVsqbWdVxrft4wHVBySh-Ze7KwbitA4T8e0CzKAB9AH23QP0qVKUpSlKUpSlQVvk1OVpFtP1KzGPIWzNNmctcFbZ4WiTMUmK2tP3Qp4L_RBPtWuZSlKUpSlKUpVyXgranLyDRPMdLJkxbsjEL4idGQrsGoc5slKE9u4D0eQo-pBc-hFWLUpSlKUpSlKrh8bHUIWfRzBNNGJK23slv71zdSgnhceEz0lKvt5ktpQB9Sjn2qnWlKUpSlKUpSs6vB01EOKbqn8MkS1IjZtj0yE2z-6uVH6ZTaj90tMyAP9s_arvqUpSlKUpSlUt-NLmL943H4xhqH0qiY7ijLvR7okyZDynPf3bbj1X3SlKUpSlKUpUwbPczf0_wB0uleUMPJaSzlVvjSFq9BGkPJYf_8ASdcrZIpSlKUpSlKVr7eJjf15Dvb1Lf8AOK24ciDAaHPIQGYEdCgPp86Vn9SaxgpSlKUpSlKUr3wJ0u2To9ygPqYlRHUPsOp9UOJIUlQ-4IBraXtc5q6W2Jc2f83LYbfR_srSFD_nX1UpSlKUpSla2e766vXndVq_OfcCz_Le9MIUBwC21MdbR_wITUR0pSlKUpSlKUrZt0EvIyPQvTrIQQRdMTtEwEHkfiQ2l_8AyrvdKUpSlKUpWsPrJf4uVavZxlEKQl-PeMkuc9l1CgpLiHZTi0qBHYghQPNdPpSlKUpSlKUpWx3slvbOQbRdIZ7DiVpaxG3QSUnkdUdlLCh-oLRH8Km2lKUpSlKVjzvi3P41ti0NvV9fu7LeW3uI_bsWgBQL781aOkPBHr5TPUHFqPA7JTz1LQDru0pSlKUpSlKUpVxHg5bkrFkGl8zbbf7ixGv-KypE-xMrUEGbbpC1POpb5PK3Gn1PKUOB8jzfAPSsiyClKUpSlKwQ8WLWncDoZgWB5Tozmj-N2qddZdtvciOw0t5x9bKXIiApxCilPS1LJ6eOSE_SqZM3z7ONSr-7lOoWXXfJLu8kIXNukxyS90AkhAUskhA5PCRwBz2ArgaUpSlKUpSlKUr6bZdLlZbjGu9muMmBOhupejSorymnmXEnlK0LSQUqB7gg8irKfC33KbrtWtwUXA8o1Tu-TYZbLLMn3lq88S3EtpSG2CmSsF0Oee416rPUkL5B9RbtSlKUpSo_160VxHcNpPkGkmaoWLffI4SiQ1_nYchCgtmQ3_aQ4lKuPRQBSrlKiDr0biNuOp22TUCTgOpVmWwrqWu3XJpJMO6RweA8w4fzDgp5SfmQTwoA1F1KUpSlKUpSlKVzGHYblWoOT27C8JsE29Xy7PCPCgQ2i468vgnsB7AAqJPZKQSSACavr8P_AGcR9pWljzN_cYl51lKmpeQSWlBTbAQD5UNpXuhvqWSr95a1nnpCQMpaUpSlKUrqupOlunesGLyML1Ow-2ZHZpPdUWcyFhC-CA42rsptwAnhaClQ57EVgFq74Kemd9ku3LRjVC7YqpalL_Zt3ji5RR9ENuBTbraR9Vl01jHlPg67ubEXFWV7CckQCegQLwtpahz25ElpoA8e3Uf1NR1K8MnfJEV0u6ESVH_VX21uD_gkmviX4cG9lB4Ogd2P6T4R_wCT1Y9X-xXfF77ccZyCA5CulolvQZsVzjrYkNLKHG1cduUqSQf0r4aUpSuwaf6f5hqnmNswDALG9eMgvLqmYMJpaEKeWEKWR1LISAEpUSSQAAanr_o1N7__AHDXD_za3f8A6K_Tfhob4XVBKdB5oJ_rXi2pH-JkV27FvCT3o5A4EXbD8fxpJPHXdL_GcAH1_opePH8OayF0v8ESUXWJetGtjSWwPx7fi8IqUo_2ZckDj-Mc8_arANBdrGhm2q1uW_SXBottkyUBEy6PqMifLA47OPr5V08gHoT0oB7hIqWaUpSlKUpSlKUrXP34MWaPvD1absIaEY5LJWvyuOPiFcKkc8e_nFzn781A9KUpWYXhOfsj_LYxT9peX8R-zbt-z-r1-I-Dc56fv5Pnfw5q-alKUpSlKUpSlKUpSsbt728nFNpOmr05LsW4Z1emHGsbsyz1dTvHHxT6QQRHbPc9wVkBCSCSpOvvf79d8pvtyyfIZ7s66XeW9PnSneOt-Q6srccVx7qUok_rXwUpSldp0t1KyrR7UOwan4TKRHveOTW50RTiSptZT2U24AQVNrSVIUARylShyOea2Jdsu5PAN0emEHUbB5KWniEsXa1OOBUi1zOnlbLnpyPdC-AFp4IA7gS1SlKUpSlKUpSlKVEG7TW-87c9AMq1gsGJpyKdY2mQ1EcdLbSVPPIZS86U_MW0KcClJTwSBxykErTrx6q6rZ7rXnVy1G1JyB-8Xy6OdTrznZLaB-VptA7NtpHZKE8AD-NdSpSlKUqUdu24_U_bFqAxn-md2DLpCWrhb5HKodyj88ll9AI5HrwoEKSe6SDWxHovqG_q3pJh-qEjHnbEvK7LEvH7OcfD5jpfaS4lIcAHWnhQIV0pJBBKUnkDulKUpSlKUpSlK8EgAkngD1NUs7v_ABWdXtQr9fMA0LuSMNw-NKfhIvFudKrndWkLUgPJkcD4ZtYCVpDQDg93CDxWYmwm_p3XeH7P00zW8ybjNaYu-E3KZKUXHgFoK47nJ7ktsyWAlXfu16kg1SVkVgu-J5Bc8Wv8NcS6WaY9b5sdf5mZDSyhxB49wpJH8K4-lKUpSu_6AaTXLXTWjDtJbYHgvJbqzEfcZ462IoPXJeHPb8NlDrnv-T0NW5-Ldq1ddG9u2JYRp7fZGO3G_wB-jtR1W-QuO-1AgN-afJWhQUjpe-D7g9h296hLYj4pWpd-1AxjQ_X4RL_GyCY1abdk3AjzWJDhKWUSQkeW-lSy22FAIWCoqUpwntbHSlKUpSlKVAm4je_t22zMvRc_zRuXkCEdTeO2gJlXFZ45AUgEJZBHcF5SAfYn0qr3cF4s-4fWB97GNIY383NjlqMdv9mLMi8SQrlIBldILRPKSAwlC0nt1qrOvXrIp-y7w6HbPNvjr-ZSbMiw_GvzFrflX249SpkhLqyVrWkuS30kknhoew7UU1Z34IupQiZfqPpDLlqIudvi5DBZP5UqjuFiQQf6yhIj9vo329DXR_F12vT9OdXBuAxu3k4tnziUXFTaflhXlKPnSQB2D6EeaCSSVh_nj5ea_KUpSlKuF8InaHMwPGXtzOe2_wAq8ZXCEbGIzqCFxrWshS5RB_ef6UdB45DSeQSHuBAHjQ6kDI9wmNacxZKHI2G48l15APJamTXC4tJ-n4LUU_3qr_hTZltmMXG3ynY0qK6l5h5pZQtpxJBSpKh3BBAII9CKvR1qv173XeHhC1s03vE605jbbKzmFvl2eU6xJh3OElaLgyytopX1dImsp44JJT29qwz27eMTq9gio1g15sjWfWVJCDc4wREuzKefU8AMyOB6BQQo-pcNWf6B7sNCNytrE3SrOok2chsOSrPK_o9yijtz1x1fMUgnjrR1IJ9FGpepSlKVGGvW5TRvbXjH8p9WswjWwPJWYNvbPmz7gpPHKY7APUvgqSCrshPUOpSQeaqO3O-LHrhrEuZjOkgd02xRwqb8yG_1XiW3yQFOSQB5HICT0M8KSSoFxwVg1IkSJch2VKfcefeWpxxxxRUtayeSpRPcknuSaye8NfRoazbuMQiTYyXrTiSlZXcgTx8kRSSwOP3gZS4ySk9ikq9fQ5E-NTrOb3qJh2hVrmFUXGoSr5dW0LBSZkn5GULHqFNsoUofaV7-1atZDeH9qmdIt3OneQvvrbgXO5CwTwlQCVMzkmOFL5_dQ4426f8Aw_f0q_nVDTPDNY8CvOmuoNnbudhvscx5TCuxHcKQ4hX7jiFBK0qHdKkgj0rX33ebRtQNpWoz2M5FHen43cHFu4_f0NEMXCOD-VRHZD6AQHGyeQeCOUKSowRSlKVYD4cPh4ztarpA1u1nsq2NPYLoftltko4VkDyT2JSf-qpI-Yns4R0jkdRF0rbbbLaWmm0oQhISlKRwEgegA9hWtfus1POsu47UTUhuY3KiXe_SRb3m_wAq4LKvJin1PP4DTXf0J9OPSopq2_wV9ZWr1heb7fr1Jbdds76cgtbDqwouQ3-GpSEoP7iHUsqP3lH-Nc-6vRtegW4XONKkNKRBs90Wq2dSlKKre8A9FJUruo-S42FHv8wV3qM7Pebvj10i3uwXWZbLjCcD0aZDfUy-w4PRaFoIUlQ-oPNWFbX_ABgdSMEchYnuKtjmbWFJDQvkRKG7vFRx6rT2blAcJHfy191KK1ngG1_SbWXTHXPEmc30pzK35FaHSELciufiR3ekK8p9pXC2XAFAlC0pVwQeOCCe6UpWH-_DxAsX2o2n-R2JNRL_AKl3JjzI0BxRVHtbSh8siX0kHv6oaBClepKU8FVHuo-pmfau5dNzvUvKp-Q324K5emTHOTxySEISOEttp5PS2gJQkdgAK6zSrYvBBtmDtWPU28IvsZzMZUuFGctiiA8xbGkKUl9A45KXHnlpVwSAWW-eOR1Yd-I1pvrDhW6fMsk1Ytqg3l9yfuNiuTPK4sy3JIQw22vgfOy0GW1oPCkkA90qQpWMNftl56M83IjuradaUFoWhRSpCgeQQR3BB962XtuOqsbW_QnBtVWHWVuZDZo8iYGlBSG5qU-XKbBH9R9DqP7voPSuc1P0s0_1mwydp_qZjEO_WK4p4djSEnlKgD0uNrHCm3E8npWghQ9iKqV3K-DzqlhcyVkW3a5jNrCVFabPNebj3aKn-qFK6WZIHc8gtrPYBCj3OBmaae57pxdP2JqDhV8xqf34jXa3uxHFAepCXEgkdx3HbuK6_UlaVba9e9bpLLGlmlGRX9p8lKZjUQtQkkf15TvSwj-8sVZjtP8AB-x7D5sPOdzlzg5NcGFIfj4vAKjbmlg8gynT0qk_u8tBKW-QQoupVxVlEaNGhRmocOO2xHYQlppppAShtCRwlKUjsAAAABUO7ytVv5ltsOomoDMox50WzOw7c4nupM6URHjqA9-l15Cj9kk-gNa31Kzn8I3TXWG77k4Wp-G21TWHWCPKg5LcJHKI7zbzB6IqDwfMd8zyXelP5QhJUQCAruHjXWzB2ta8IvNmvEV3KJVgdi3yA0sFyOw06FRHXAPRTgefA579LKfbjmuilSFofr5qpt2zVjO9KcokWqcgpTJjklcWeyDyWZLJPS6g9_XuknqSUqAUL2NmW9fT7d5h63raluy5paGkqvePOO9S2geB8QwT3dYKiB1eqCQlYHKSvI6oi3W7grNtk0NyHVe5ttSZkNsRbPCcVwJtxd5Sw16glIPK18dw22sjuK1zMyzHJ9QcquubZpepF2vl6lLmT5sggredWeSe3AA9gkAJSAAAAAK4elK7VphqjnejWb23UTTfIpNlvtqc8xiSyeyk_vNuJPyuNqHZSFApUOxFXM6Hbg9vXid6Py9INY8bgQcxjtefOsvm9LjbyElKbla3lcrHHUeR3U31Kbc8xtXU7WRvJ2Uai7RMuSzdQ5esMurykWTImmilt09z8O-B2akBIJ6eeFAFSCQFBOOdXF-Cxq8ch0jy7Rm4y1uSsQuibpb0rKQEwZgPU2gDuQh9p1aifeQO_sLHaV6JkKFcI6olwiMyWF_maebC0K_UHsa4SNpzp7CkCXDwTHWHweQ61a2ErB_UJ5rsIASAlIAA7ACvNKrK8bLVpNuwnA9EoEvh-9T3chuKEOcKTHjpLTCVp90LcedUOe3VHB9QKqMrLvYx4feZ7rbs3l2TqmY7ppCfKJV0SgJfuS0nhUeGFAgnkFKnSChB5HClAprO7dhvV0g2I4DG257bbDaVZfb4Yjx4EYeZDx5Chz58tRJL0pfJWG1ErUVeY6eFJDtNeVZVkmcZHccvy-9S7vertIVKmzZbhW6-6o91KJ_wA9AAAOAK4qlK7lo9qzmWh2pFj1RwK4GJeLFJS-2CT5b7fo4w6AR1NuIKkKH0UeODwa2R9IdT8c1o0xxrVTEnCq15Nbmp7KFKSpbClDhxlZTyOttYW2oA8BSFCquPGw1ekXLPMH0OgSViHZbevIrghJHQ5KkLUywFD16m22nSPtJ9_as2lKUrk8YyjIsKyG35ZiV6mWi82p9MmFOhulp5h1PopKh3H_uCQe1Xu7SNRZ2-PaBKlbnNP7S_bbg7Js8x5Z8uNeY8cI5npSODGWlzqHUhQ6XWFONlv5Uooly5jGo2WXqNhcyXLx5q4yUWmRMSA-9DDqgwtwAJAWW-kq4SO5PYelZG-GprInRvdziMmbJSzacuK8UuKlJJ-SWUhg888JAlIjEqPYJCvT1GwLSlKUpWvf4jesH88u7jNbnFk-da8afGMW3t2DUMqQ6QfdKpBkLB-ixUYbbMc07zDXzAcU1YckIxO8X6JBufkO-UVIcWEpSpY4KG1LKErUCFJQVEEEAi4LxIdftQ9oehWMY_oLiECx2y-OOY-i9Rkobbx9LbSVMsR44T0hx1sPdC_RsML-UqUlSaOp06bc5si5XKY_Lly3VvyJD7hccecUSVLWo8lSiSSSe5Jr00pSlXCeCtrC_f9L8y0VucpS3cSuDd2tgWodocwKDjaB_VQ80pZ595P-Ff3iA51_OHvG1SvaXVLahXtVkaBJISmAhEQ9P0BUwpXbsSon35rHylKUrmMLxO8Z7mNiwXHm23Lrkdzi2mChxXSlUiQ6lpsE9-AVLHeroN9mY2DZjsQtehuCSfLn323tYXbVgJS6uP5XNwmLSOO60dYUpPo5KSeOKpHr2R5EiJIalxH3GX2VpcadbUUrQsHkKSR3BBHIIrZS2v6xxtftAsJ1YacbVJvdrb_aKUJ6Utz2iWpSAPYB5tzj6p4PoalKlKUqKd1OsbGgW3zONVVPIRLs1rWm2hSCoLuDxDMVJSO5T5zjfV9E9RPABNa17zrsh1b77q3HHFFa1rUSpSieSST6kmvzV6GEzYPiM-Hc7ZrjJZkZa9bFWyU66sBTGRQQlTTq1D8nmkMuK4_wBHII96o1mQ5lumP2-4RXosqK4pl9h5socacSeFIUk90qBBBB7givTSlKVmN4T2oqMC3gWm3ynwzByqy3O0SXFK4QhKGfi0qP8AeiJSP9r9axf1Pn3K66lZbc7yw4xcJl8nvy2nPzoeXIWpaVfcKJBrrNKUpXNYRmN-08zKx55i8oRrxj1wj3OC6RyEvsuBaOR7jlI5HuOR71djuVwnG_EU2N23UnTuCl7JIsI5DYWE8KeanNJKJltJ9SVdLjQHZJcQyr0AqjSlWteClril2Lmm3e7SlFxlQyqypWVH5D5bEtsE9gAr4ZYSPUrdVx6mrTqUpSqs_Gu1uSzBwrb1aZZDkhZym8oQojhtPWxEQeOygVfEqKT6Fts8ehqqOuQx6wXnK7_bMWx23uz7teZjNvgRGuOuRIdWENtp591KUkD7mrxczuuN-GTsPj2eyOxHsrTH-BhOBHIuORSklTsggjlTbfC1gK_0TCEc88VRhOnTbnNkXK5S35cuW6t-RIfcLjjriiSpa1HkqUSSST3JNemlKUrvmhd0yGy6qWS54rFdkXRn4nyG2uepXMZ1KuOP7JUazz8Rrw49QWdQrxrvoHi0vI7Pkkhc-92O3NF2bBmrPLrzLKfmeacWSshAUpClK-Xo4Ka3LxZbxj1yfs9_tMy2T4yul6LMYWy80eOeFIWApJ4I9RXx0pSlWMeDvuZOD6kXLbplFw6LLm6jPsZcUAmPd22_nbHbt57KAOSfzx2kpHLhqM_FI2xnQfX-RmuOwC1iOoy3rxC6E_JFn9QMyN69h1rDqRwAEvBKR8hrDOpX2ra0ydvm4DC9Vm3lph2m5IRdEJBV5lueBalJ6R-Y-UtZSO_C0pPHatk2PIYlx2pUV5DrLyEuNuIVylaSOQQR6givZSleqVKjQoz0yY-2wxHbU6664oJShCRyVEnsAACSa1tN1WtcrcJuAzPVZx5xUK63FbdqQsFPlW5kBqKnpP5T5SEKUBxytSzx3qJ6sn8HXa-cqzafuYyy3k2vFVuW3HEuJIS_clt8PPgeikstL6RyCOt7kEKaqGPE83N_5QO4SVjuPXAP4fp6XrLa-hQLcmV1D4yUDx36nEJbSQSkoYQocdRrD-lKUrlsXxHLM4u7eP4XjF2yC6PAqbg2uE7LkLAIBIbbSVH1Ht7irWPDZ8OTNdM8xY191-tLVsuMKM81YMdcWl15pbzamnJMoJJQn8Ja0paJUeVlSghSEg2dVwmU4Rhmc29VpzbEbLkEFaSlUa6wGpbSkn1BQ4lQI_hUB5x4b-y_PFl-foha7XI4IS7Y5Mi2hPP-rYWlo_xQagLNfBQ0JuqH3ME1RzPHn3AS0mcmNcY7SvbhAQyspH0LnJ-tQXmXgkaxW8dWA6yYhfAFdxdYsm2qKeD3HliQCeeOxIH3qGMr8KnetjLpELTWBkLIBJftN8hqSP7jzjbh_gk1FGSbOd1mJvKZvW3jPx0glTkWxSJbQH3cYStH--uhOWnUTS3ILdfJllvuMXi1y2ZsF-XCdiusyGlhba0-YkfMlSQR-lXY5BBxvxONhjU-3IhNZa5G-JjJ6wkW3JYiSFtE8nobd6lJ5PJDMlKuOeKownwJ1qnSbXdIT8OZDdXHkR5DZbdZdQSlSFpUAUqBBBBHIIIr0Vfx4YmtCtY9pWNM3CUHrxhK14rPPBBKY6UmMruST_RlsAq91JX-gywpSsOfFR16To3tfuWMWyWlu_6jLVjkRAUOtMNSOZrvB7lPk_hEj0VIQaodrtGl2m2U6wah4_pjhUMSb1kc5uDFSrnoQVH5nFkAlLaEhS1q4PCUqPtVzu7rUfF_D72V2fSLS6aIuQXKCcbx5YKUSCsp6p1zUEkcLHmKWVJ7B6Q124NUsY3p_nmYnjEMJv8AfDzxxbba9J7_AE_DSalDFtke7nMV9Fm275w39F3G1OW9B-4VJ8tJH3BqWcS8Jbejkqj-1cNsOMJ6gAu736OoKH14il4gfqAftUyYh4IWp81kKz3XPF7M6SeU2i2SLkkDnt3dVH9uPb_7qdcP8FjbpaFsyMwz_OMhcb4K2mn40KO79QUpaU4B-jgP3qe8I8O7ZlgXz2vQexXB08FTl7U9deo_XplLcQP0CQKnrHsYxrErei0Yrj1ss0FsAIi2-I3GaSB6AIbAA_wrk6UpSlKV4UlK0lC0hST2II5Br54dut9uS4m3wI8VLq_McDLSUBauAOo8DueABz9qxq122_6Dz7jdL_O0TwKRc57plS5ruNw1vyH3D1LcccLfUtalEkqJJJJJrB3WDSfSy2PThbdNMViBCCU-RZozfHr6cIFTN4QTLMKRrHb4bSGIrb9jcQw0kJbStQnBSgkdgSEpBPv0j6CrGqUqp_xj_wCmaz6VQJf48VFkmuJYc-ZsKVJbClBJ7ckJSCffpH0ridAtJNKby3GN30yxOd1NAn4myxneT_eQasX0T0P0WwpDeU4bpBhNhvSEqZTcbZj8SLKS2pI6kh1tsLCT7jng1KUyyWW4ymZtwtEKVIjpKWnno6FrbB9QlRHIB4HpX2AAAADgD0FeaUpSlK__2XFlbGVtZW50SWRlbnRpZmllcmhwb3J0cmFpdNgYWLSkZnJhbmRvbVggDvAWRA3_FVJs3PNtgC8pqMcmYFlxRNRMD4W22v3lXfJoZGlnZXN0SUQGbGVsZW1lbnRWYWx1ZYGjamlzc3VlX2RhdGXZA-xqMjAyNC0xMC0wMmtleHBpcnlfZGF0ZdkD7GoyMDI0LTEyLTMxdXZlaGljbGVfY2F0ZWdvcnlfY29kZWJCMXFlbGVtZW50SWRlbnRpZmllcnJkcml2aW5nX3ByaXZpbGVnZXPYGFhtpGZyYW5kb21YIF4wQrdVKkfY7pNwP_8egPbfgG2Pnf4VVm4x2gut7agQaGRpZ2VzdElEC2xlbGVtZW50VmFsdWViRkNxZWxlbWVudElkZW50aWZpZXJ2dW5fZGlzdGluZ3Vpc2hpbmdfc2lnbtgYWGSkZnJhbmRvbVggJMzCv87ZukPmke2Fn5KzhLludM7yTHzRJ-OJgV3BHiRoZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZWRhZ2FscWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1l2BhYZKRmcmFuZG9tWCAUIXcVP7J8gRXrmlsT8F1ShthDS4Uz7C_beJGBChQ8e2hkaWdlc3RJRAlsZWxlbWVudFZhbHVlZXhlbmlhcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVqaXNzdWVyQXV0aIRDoQEmoRghWQLoMIIC5DCCAmqgAwIBAgIUcjJt9mMImntQD4w_JqaFy8LC0sowCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAxMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTIzMDkwMjE3NDI1MVoXDTI0MTEyNTE3NDI1MFowVDEWMBQGA1UEAwwNUElEIERTIC0gMDAwMTEtMCsGA1UECgwkRVVESSBXYWxsZXQgUmVmZXJlbmNlIEltcGxlbWVudGF0aW9uMQswCQYDVQQGEwJVVDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEkEfNQcLRumao61kGFlsOaT3hsc5a96bVyK937SPd6yfyrwvUwIKiU2pCQI9p1eMkBiyZdLcPj4cH2xw6yGLFijggEQMIIBDDAfBgNVHSMEGDAWgBSzbLiRFxzXpBpmMYdC4YvAQMyVGzAWBgNVHSUBAf8EDDAKBggrgQICAAABAjBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX1VUXzAxLmNybDAdBgNVHQ4EFgQUge_0nFyDClCmRr73UHhaUz4_2JswDgYDVR0PAQH_BAQDAgeAMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwIDaAAwZQIwRfraou8tlVPrtIhE2GQa0CqeOo5KK3fa4vQeeV8vLZCbA_KBCZRrTi2Sg61_waGFAjEAm55O7VAQn18OtwAsz5iz_uQRQH5l7jD7AQS-1nOC6oPeH1zEiOYQF2QBMidDQE0KWQLc2BhZAtemZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTEwLTAyVDA3OjE5OjA0Wml2YWxpZEZyb23AdDIwMjQtMTAtMDJUMDc6MTk6MDRaanZhbGlkVW50aWzAdDIwMjQtMTAtMDlUMDA6MDA6MDBabHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGsAFggK8EVuClyEZ0HS1Gs0xPDAUhcb8ztd1lq-OZ3ApeKFSgBWCD1mL6S52VQIVOjXm-51wQjr2m_pVLQ5rneSGfnUMSehQJYID7d5l6R8fXefUcz9pRNG1OQSty3NaUaur3As54DDJGhA1ggb0pbPSYf2LEtTqoSg73MYC6Lm8jMr1js3BglqZegNt0EWCD7IsbGlSuDCy9A_OED8FZeN4KR2-n9jZTLlGSdBPNPDAVYIPU8Vhmfz4nDpyXzN0CytwevOG9sk05CwZ82vxwQX8DEBlggh1bG6lafbcS2QidihopDy9fn1qWGwuGm3C7grH2-thUHWCBZ00mLs3QgSBMWnb0UHRLTwcHSJNklEjoytrifuq3FhAhYINhyahU9dAKuMc_NMqGVLoS1IooabaK3pE7E2GXw7YXlCVggiGPX3Scs-C9NN9YlsfIRdNkEpDu4iIoNIJJo8g_hut0KWCBrDNqy-YxdB9uGd19czhWY-sWr12q4k-zq1o5z7ZL6-gtYIH2tym9bCuA10f4tWHdaqmKphnH0Q3e1CgjRQ27vN6tKbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVgf3f4eilIQCB1GqjZtdnsIIiM5pEBvNqnfOzn53q2veyJYIBMmEudvxlgqJ024ifXKm7FBjoBr72eK8TZUMnskMp1ub2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2WEAK2pYyRkYQfPe-eb3IA4Jlxxnc9Z6yp_Ch13Vy5WfRHzhKD-1_N3V1Rlp1dUyUfi-H_pfDmESUCucjYseD2tyLbGRldmljZVNpZ25lZKJqbmFtZVNwYWNlc9gYQaBqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhAqO1ceqFg3TCWb7LNdtp_Vr0myOACZR9HCDYJ-wd25YeG4UG30QfyAqn84eh5CBxvPDK-7YzlCYPRJ2RNMwp8zWZzdGF0dXMA
        """.trimIndent()

    /**
     * An mDL with invalid chain
     */
    val MdlVP =
        """
        o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xhNgYWImkZnJhbmRvbVhA749knalJ0xgtGBK1lVhhXe8D-beFtIiXyln1UhmTPKmbNmTwvolOya3h-_AyFE2MqCom3sBYs8VylU238nkOTGhkaWdlc3RJRA5sZWxlbWVudFZhbHVlaUFOREVSU1NPTnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWIOkZnJhbmRvbVhAvzy0xTmV9BWSqTH1L5LO5KFazP-kCsBiHu3agh_dFhynMj0SLBaWYfNPrXPSK7wUIwuPquplYgA4Lb1zGEFzt2hkaWdlc3RJRBgmbGVsZW1lbnRWYWx1ZWNKQU5xZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWI2kZnJhbmRvbVhAvDJWC3eMvjG57CkfQlaBdjIY7Yf2NNvTr27KpwdQ4kYrSSQhsOJATDiIXZeAP7bVqdvdO7Zni0NUIVDHSteSSGhkaWdlc3RJRBhCbGVsZW1lbnRWYWx1ZdkD7GoxOTg1LTAzLTMwcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGXYGFiUpGZyYW5kb21YQO13H9R-OzlZjjFEcIwqERO9RaruJZWsGolT5X6qpSvMEGGCjBOMx1mVl2jl24K-C_pe-SdAEFhwc_KcXkoBI7VoZGlnZXN0SUQPbGVsZW1lbnRWYWx1ZcB0MjAwOS0wMS0wMVQwMDowMDowMFpxZWxlbWVudElkZW50aWZpZXJqaXNzdWVfZGF0ZWppc3N1ZXJBdXRohEOhASahGCFZAoUwggKBMIICJqADAgECAgkWSuWZAtwFEGQwCgYIKoZIzj0EAwIwWDELMAkGA1UEBhMCQkUxHDAaBgNVBAoTE0V1cm9wZWFuIENvbW1pc3Npb24xKzApBgNVBAMTIkVVIERpZ2l0YWwgSWRlbnRpdHkgV2FsbGV0IFRlc3QgQ0EwHhcNMjMwNTMwMTIzMDAwWhcNMjQwNTI5MTIzMDAwWjBlMQswCQYDVQQGEwJCRTEcMBoGA1UEChMTRXVyb3BlYW4gQ29tbWlzc2lvbjE4MDYGA1UEAxMvRVUgRGlnaXRhbCBJZGVudGl0eSBXYWxsZXQgVGVzdCBEb2N1bWVudCBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR8kxP0waSqTrCz62gRpJlOWd5nmWQxwvOuCI63oQYctli9jDkSbBlZeskN-Z0HjT7zkTujS9ssvGmH0Cfpr538o4HLMIHIMB0GA1UdDgQWBBTRpLEkOTL7RXJymUjyUn2VWKdNLTAfBgNVHSMEGDAWgBQykesOHAEdFA52T2xP6kyWONr7BDAOBgNVHQ8BAf8EBAMCB4AwEgYDVR0lBAswCQYHKIGMXQUBAjAfBgNVHRIEGDAWhhRodHRwOi8vd3d3LmV1ZGl3LmRldjBBBgNVHR8EOjA4MDagNKAyhjBodHRwczovL3N0YXRpYy5ldWRpdy5kZXYvcGtpL2NybC9pc28xODAxMy1kcy5jcmwwCgYIKoZIzj0EAwIDSQAwRgIhAN5fmOce9ldSEmvyxLhP3t-B0kPKV7Fb0xiqufHr6z99AiEA_iL3MmtLV1j_Fv6G0zqNjSmIIWnaBJtaXiyAarFHCEhZBmTYGFkGX6ZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZnZG9jVHlwZXVvcmcuaXNvLjE4MDEzLjUuMS5tRExsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMbglDlggkkOj-6hAjWfN8o9jhSncYFJQ0fDBxRBStdnWv_8nZB0YJlggHD3d1-rVoh_It7pmbn7ZZjSb1OtaHXET-vOpPKgXvdcYQlgg_PH--h2tMOyeAMIK_AyyAqgMeSmpqSyh-fKp-RzvR5UPWCAtYbt8x-FV3n8vug3QNaDzTW9NZYR6EKYxapriNQk-egpYID5ee-HsMz5HD4NRZYEYmqYhapqw3TILJx4tIjom6SvOBVgg_72Y-M6CJBy7beNYhE6bpTlEkRIbQ1A4p25E3_MrKQUYWVggHyw4N0q-2ZY-7HWGb4VNqCSJuQ7dCWN5P1VNuSjiPv4YZlggx1SWAXewxOaPu022Kcx7T7wTjc4y7vmLtgtKYOUuoHwYGVgg8hoS1uF5wPOckGMZ-uwJ5i_dfrB49w45fuP6WFrGnagIWCCpXnUkg0HFUsG2ooBy19RM2wMXZlC9fsDCgFu40KiDaBhAWCASqDJUAZeie5vDlaT-WVf6aQ5_TC225Gk0dFXPc1Uy7A1YIJTv_fqKHmZ1jVrB_Jh4rZLmgRQ4lMi59JqA6u45gaFLGDJYIANaiahebONUwWUXoizeac8ArnfaVjqaK3SOSkktKtNqGCFYIKJ--Ol3d5RmvL-C9lyTl-SLCyDLXFohrX0uZPn4F_ZDGD9YIOymcKB-tuLfl75WvkFgQ3V29nolL1wrR-VtuPUUiJZpGC5YIIYCq9EgqzXF_1xfpBomrXEv_UT1DJIZnpbkOYAFZjWaGElYIM8ineKdyI5xQH704kgiNsTwBPHqiX4Fl95h8aCm0ysHCVgglhk1fNxfOyp6WD7KQ9SxlYVvIZv71KdXUe2o3rOpmWEYJ1ggzNeoHyw9M_D7sAdqm_4Wk26gfRT4N_ECn95zZUDJlmsYX1ggU-obG-GsD2yYjRFJjW4Zzhpt1oWwCN6sw5cDkDnZU0UYKlggMJpODSrV3RosBjudUNh186RnBTJuE4mLsxy9BdJzssoYT1ggcj9wzitw_eHjhExGvXUnqLzzSRHKUzmVXkdheGyXjHQYSFgguv6QoagYTCfTHxwqejsNIddHIBr1epPrEtf6kmTFqggYPVggGSy9_z8QoAyHJWohY5qk6J1ts3uEOw2NZ7UzQ2hhhzsYU1ggelpUst7GN_S83C10Kl6TV-67vlp1KrCjQ1eUw_IOEZEYUFgg7l1_1kX6wsqid3gqMAmUpytUaF6rbvzJa8qBho5UtFsYQ1ggRFYV3ASPVs91_Pq49A8-FPBWMSlGfJEDtx6U9QGDdYcUWCCddIVod3NO1J-CianCUPazTCSmR5EoxYod8OICcR7M0BhSWCAg4D5ttNjoHKpkGFk9fXx7rzM5I8uK3-z3DesxaPW6Vxg5WCAYgBGGSyFyThlECkdExwQlV6vK-IaeGbxEcTZT1-jAaxhiWCA6joyHq7zvmdx5dGECtdbVbMde-zzoxNAsEs_0tISBKBFYIIJEG-CdR1CN7xp6lnwmj0y9yMX0UQAZfcy0rC48nKIxDFggRo6NNXweSIpoI8c4NSda5R9zHjO43AXc0bkiUofwnKkYOlggOyBuX5Her6s_ZFG9VRCaCX_ImtnSfzYF_MP8r9raUVUYTVggG9Sqh2I18AmWpxYTrGsfv4jh3PS_5o8zCOOLdTV5MUAYVlggKbH3AZnwQU6448Ef4-NV3dBwAkAYjkk6s0ezs0lE0mMYVFggR-sRxzD1B4U224dBR5Zk-vixJXwOFBIWXcysExJN99NtZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCBDDtpcwH3siSXBoDgBOGFYu_d7YJTeHlSEUvE3I851ASJYINkipi0KQaoI8x6Lu2WNQJLJY8WgUaT6n-WkEj1KiRm_bHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI0LTA5LTAzVDA5OjQ2OjE2Wml2YWxpZEZyb23AdDIwMjQtMDktMDNUMDk6NDY6MTZaanZhbGlkVW50aWzAdDIwMjUtMDktMDNUMDk6NDY6MTZaWEDrktGVkgavhQ4LnnkyDUi_YvxF1M4gJt15CUuYvjbPb6Qnsg8OpFC1GT_D2MdJhwYMEVbY4z-qCRqrA8yIWMJqbGRldmljZVNpZ25lZKJqbmFtZVNwYWNlc9gYQaBqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhAQyIROFA1Q6OQx7eBYqxxBX52xAhYj_aMuTI9M8ZwoRfNP0RuMUn45LwrkeoaJGg4ksiD9rcqh1qG9NBF9nadu2ZzdGF0dXMA
        """.trimIndent()

    val caCert: X509Certificate by lazy {
        val certificateFactory = CertificateFactory.getInstance("X.509")
        val certStream = ClassPathResource("PIDIssuerCAUT01.pem").inputStream
        certificateFactory.generateCertificate(certStream) as X509Certificate
    }
}

class DeviceResponseValidatorTest {

    @Test
    fun `a vp_token where the 3d document has an invalid validity info should fail`() {
        val invalidDocument = run {
            val validator = deviceResponseValidator(Data.caCert)
            val validated = validator.ensureValid(Data.ThreeDocumentVP)
            val invalidDocuments =
                assertIs<DeviceResponseError.InvalidDocuments>(validated.leftOrNull())
                    .invalidDocuments
            assertEquals(1, invalidDocuments.size)
            invalidDocuments.head
        }

        assertEquals(2, invalidDocument.index)
        val documentError = run {
            assertEquals(1, invalidDocument.errors.size)
            invalidDocument.errors.head
        }
        assertIs<DocumentError.ExpiredValidityInfo>(documentError)
    }

    @Test
    fun `a vp_token where the 3d document has an invalid validity info should not fail when skip`() {
        val validDocuments = run {
            val docV = DocumentValidator(
                validityInfoShouldBe = ValidityInfoShouldBe.Ignored,
                x5CShouldBe = X5CShouldBe.Trusted(Data.caCert.nel()),
            )
            val vpValidator = DeviceResponseValidator(docV)
            val validated = vpValidator.ensureValid(Data.ThreeDocumentVP)
            assertNotNull(validated.getOrNull())
        }

        assertEquals(3, validDocuments.size)
    }

    @Test
    fun `a vp_token having a single document with invalid chain should fail`() {
        val invalidDocument = run {
            val validated = deviceResponseValidator(Data.caCert).ensureValid(Data.MdlVP)
            val invalidDocuments =
                assertIs<DeviceResponseError.InvalidDocuments>(validated.leftOrNull())
                    .invalidDocuments
            assertEquals(1, invalidDocuments.size)
            invalidDocuments.head
        }
        assertEquals(0, invalidDocument.index)
        val documentError = run {
            assertEquals(1, invalidDocument.errors.size)
            invalidDocument.errors.head
        }
        assertIs<DocumentError.X5CNotTrusted>(documentError)
    }

    @Test
    fun `a vp_token having a single document skipping chain validation should be valid`() {
        val validDocuments = run {
            val docV = DocumentValidator(x5CShouldBe = X5CShouldBe.Ignored)
            val vpValidator = DeviceResponseValidator(docV)
            val validated = vpValidator.ensureValid(Data.MdlVP)
            assertNotNull(validated.getOrNull())
        }

        assertEquals(1, validDocuments.size)
    }
}

private fun deviceResponseValidator(caCert: X509Certificate): DeviceResponseValidator {
    val documentValidator = DocumentValidator(
        Clock.systemDefaultZone(),
        ValidityInfoShouldBe.NotExpired,
        IssuerSignedItemsShouldBe.Verified,
        X5CShouldBe.Trusted(nonEmptyListOf(caCert)),
    )
    return DeviceResponseValidator(documentValidator)
}