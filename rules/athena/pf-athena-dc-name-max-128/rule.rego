package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-dc-name-max-128", "ERROR", name,
	"Properties.Name",
	sprintf("the data catalog name is %d characters; CreateDataCatalog fails with \"DataCatalog name ... is invalid.\"", [count(n)]),
	"Use a data catalog name of at most 128 characters",
	"https://docs.aws.amazon.com/athena/latest/APIReference/API_CreateDataCatalog.html") if {
	some name in resources_of_type("AWS::Athena::DataCatalog")
	n := resolve(name, "Properties.Name")
	_pf_athlib_lit(n)
	count(n) > 128
}
