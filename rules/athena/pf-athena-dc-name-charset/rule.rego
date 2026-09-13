package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-dc-name-charset", "ERROR", name,
	"Properties.Name",
	sprintf("data catalog name '%v' has characters outside [a-zA-Z0-9_@-]; CreateDataCatalog fails with \"DataCatalog name %v is invalid.\"", [n, n]),
	"Use only letters, digits, underscore, at sign and hyphen in the data catalog name",
	"https://docs.aws.amazon.com/athena/latest/APIReference/API_CreateDataCatalog.html") if {
	some name in resources_of_type("AWS::Athena::DataCatalog")
	n := resolve(name, "Properties.Name")
	_pf_athlib_lit(n)
	not regex.match(`^[a-zA-Z0-9_@-]+$`, n)
}
