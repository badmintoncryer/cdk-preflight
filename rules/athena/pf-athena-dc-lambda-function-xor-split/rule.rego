package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-dc-lambda-function-xor-split", "ERROR", name,
	"Properties.Parameters",
	sprintf("the Lambda catalog sets both 'function' and '%v'; CreateDataCatalog fails with \"Lambda catalogs require that either the metadata-function and record-function parameters or the function parameter be set, but not both.\"", [k]),
	"Use the single 'function' parameter, or the 'metadata-function' and 'record-function' pair",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-athena-datacatalog.html") if {
	some name in resources_of_type("AWS::Athena::DataCatalog")
	resolve(name, "Properties.Type") == "LAMBDA"
	params := _pf_athlib_params(name)
	_pf_athlib_has(params, "function")
	some k in ["metadata-function", "record-function"]
	_pf_athlib_has(params, k)
}
