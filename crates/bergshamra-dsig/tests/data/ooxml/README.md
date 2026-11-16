# LibreOffice partial-coverage OOXML fixture

`partial.docx` is the unchanged genuine signed package from LibreOffice/core,
`libreoffice-26.2.0.3`, `xmlsecurity/qa/unit/signing/data/partial.docx`:

https://github.com/LibreOffice/core/blob/libreoffice-26.2.0.3/xmlsecurity/qa/unit/signing/data/partial.docx

Its original MPL-2.0 license is retained in `LICENSE-MPL-2.0`. The signature
XML and eight referenced package resources in this directory are byte-for-byte
extractions, allowing the tests to use the existing exact URL-map resolver
without a ZIP dependency or ambient network access.

The signature has three `SignedInfo` references and one embedded `Manifest`
with eight references, including two OPC RelationshipTransforms. It signs only
part of the package. LibreOffice's `testOOXMLPartial` expects `PARTIAL_OK` or
`NOTVALIDATED_PARTIAL_OK`, not complete package coverage:

https://github.com/LibreOffice/core/blob/libreoffice-26.2.0.3/xmlsecurity/qa/unit/signing/signing.cxx#L625-L640

These tests establish XML signature and declared Manifest member integrity.
They deliberately do not establish X.509 trust, Office application acceptance,
or integrity of package parts absent from the Manifest (for example,
`docProps/core.xml` and `docProps/app.xml`). Altered-body tests mutate temporary
copies only; the original fixture stays unchanged.
