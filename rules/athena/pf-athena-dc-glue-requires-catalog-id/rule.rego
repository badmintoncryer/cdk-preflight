package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-dc-glue-requires-catalog-id", "ERROR", name,
	"Properties.Parameters",
	"the GLUE catalog has no 'catalog-id' parameter; CreateDataCatalog fails with \"Glue catalog parameters cannot be empty.\"",
	"Set Parameters.catalog-id to the AWS account ID that owns the Glue Data Catalog",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-athena-datacatalog.html") if {
	some name in resources_of_type("AWS::Athena::DataCatalog")
	resolve(name, "Properties.Type") == "GLUE"
	not _pf_athlib_has(_pf_athlib_params(name), "catalog-id")
}
