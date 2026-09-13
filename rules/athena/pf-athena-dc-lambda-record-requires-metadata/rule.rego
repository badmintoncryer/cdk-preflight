package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-dc-lambda-record-requires-metadata", "ERROR", name,
	"Properties.Parameters",
	sprintf("the Lambda catalog sets '%v' without '%v'; CreateDataCatalog fails with \"Lambda catalogs require that either the metadata-function and record-function parameters or the function parameter be set, but not both.\"", [pair[0], pair[1]]),
	"Set both 'metadata-function' and 'record-function', or use the single 'function' parameter",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-athena-datacatalog.html") if {
	some name in resources_of_type("AWS::Athena::DataCatalog")
	resolve(name, "Properties.Type") == "LAMBDA"
	params := _pf_athlib_params(name)
	not _pf_athlib_has(params, "function")
	some pair in [["record-function", "metadata-function"], ["metadata-function", "record-function"]]
	_pf_athlib_has(params, pair[0])
	not _pf_athlib_has(params, pair[1])
}
