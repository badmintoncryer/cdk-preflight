package cdk_preflight

import rego.v1

# CreateTable takes exactly one MetadataOperation value (CREATE); the property
# is documented as optional in the resource schema but the service requires it.
violation contains make_diag_full("pf-glue-table-iceberg-metadata-operation", "ERROR", name,
	"Properties.OpenTableFormatInput.IcebergInput.MetadataOperation",
	"IcebergInput has no MetadataOperation; CreateTable fails with \"Metadata information must be present\"",
	"Set OpenTableFormatInput.IcebergInput.MetadataOperation to CREATE",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateTable.html") if {
	some name in resources_of_type("AWS::Glue::Table")
	otf := _pf_gluelib_get(name, "OpenTableFormatInput")
	is_object(otf)
	ii := object.get(otf, "IcebergInput", null)
	is_object(ii)
	object.get(ii, "MetadataOperation", "__pf_absent") == "__pf_absent"
}
