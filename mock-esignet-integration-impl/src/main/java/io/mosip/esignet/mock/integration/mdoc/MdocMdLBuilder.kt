package io.mosip.esignet.mock.integration.mdoc

import id.walt.mdoc.dataelement.toDE
import id.walt.mdoc.doc.MDocBuilder

class MdocMdLBuilder {
    fun buildMockMDoc(): MDocBuilder{

        val drivingPrivilegeObject = mapOf(
            "vehicle_category_code" to "A".toDE(),
            "issue_date" to "2023-01-01".toDE(),
            "expiry_date" to "2043-01-01".toDE()
        )
        val drivingPrivilegeArray = listOf(
            drivingPrivilegeObject.toDE()
        )

        val mdoc = MDocBuilder("org.iso.18013.5.1.mDL")
            .addItemToSign("org.iso.18013.5.1", "family_name", "Doe".toDE())
            .addItemToSign("org.iso.18013.5.1", "given_name", "John".toDE())
            .addItemToSign("org.iso.18013.5.1", "issuing_country", "US".toDE())
            .addItemToSign("org.iso.18013.5.1", "document_number", "123456789".toDE())

            .addItemToSign("org.iso.18013.5.1", "issue_date", "2023-01-01".toDE())
            .addItemToSign("org.iso.18013.5.1", "expiry_date", "2043-01-01".toDE())
            .addItemToSign("org.iso.18013.5.1", "birth_date", "2003-01-01".toDE())
            .addItemToSign("org.iso.18013.5.1", "driving_privileges", drivingPrivilegeArray.toDE())
        return mdoc
    }
}

