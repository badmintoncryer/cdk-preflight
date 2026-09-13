package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-dc-hive-requires-metadata-function", "ERROR", name,
	"Properties.Parameters",
	"the HIVE catalog has no 'metadata-function' parameter; CreateDataCatalog fails with \"Hive catalog parameters cannot be empty.\"",
	"Set Parameters.metadata-function to the Lambda function that serves the Hive metastore",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-athena-datacatalog.html") if {
	some name in resources_of_type("AWS::Athena::DataCatalog")
	resolve(name, "Properties.Type") == "HIVE"
	not _pf_athlib_has(_pf_athlib_params(name), "metadata-function")
}
