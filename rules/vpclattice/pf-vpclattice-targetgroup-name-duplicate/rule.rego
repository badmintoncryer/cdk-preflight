package cdk_preflight

import rego.v1

# Name is not the primary identifier, so the schema says nothing about
# uniqueness, but CreateTargetGroup fails for a name already taken in the account and
# region ("Resource with name ... already exists in account ..."). Only names
# inside one template are compared, as written.
violation contains make_diag_full("pf-vpclattice-targetgroup-name-duplicate", "ERROR", name,
	"Properties.Name",
	sprintf("Target group name '%s' is already used by resource '%s'; CreateTargetGroup fails with \"Resource with name %s already exists in account\"", [n, other, n]),
	"Give each target group its own Name",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateTargetGroup.html") if {
	some name in resources_of_type("AWS::VpcLattice::TargetGroup")
	n := resolve(name, "Properties.Name")
	is_string(n)
	some other in resources_of_type("AWS::VpcLattice::TargetGroup")
	other < name
	resolve(other, "Properties.Name") == n
}
