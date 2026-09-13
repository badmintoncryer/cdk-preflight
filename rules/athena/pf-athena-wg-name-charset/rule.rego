package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-wg-name-charset", "ERROR", name,
	"Properties.Name",
	sprintf("workgroup name '%v' has characters outside [a-zA-Z0-9._-]; CreateWorkGroup fails with \"Value at 'name' failed to satisfy constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9._-]{1,128}\"", [n]),
	"Use only letters, digits, period, underscore and hyphen in the workgroup name",
	"https://docs.aws.amazon.com/athena/latest/APIReference/API_CreateWorkGroup.html") if {
	some name in resources_of_type("AWS::Athena::WorkGroup")
	n := resolve(name, "Properties.Name")
	_pf_athlib_lit(n)
	not regex.match(`^[a-zA-Z0-9._-]+$`, n)
}
