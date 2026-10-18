package cdk_preflight

import rego.v1

# Name is not the primary identifier, so the schema says nothing about
# uniqueness, but CreateServiceNetwork fails for a name already taken in the account and
# region ("Resource with name ... already exists in account ..."). Only names
# inside one template are compared, as written.
violation contains make_diag_full("pf-vpclattice-servicenetwork-name-duplicate", "ERROR", name,
	"Properties.Name",
	sprintf("Service network name '%s' is already used by resource '%s'; CreateServiceNetwork fails with \"Resource with name %s already exists in account\"", [n, other, n]),
	"Give each service network its own Name",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateServiceNetwork.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetwork")
	n := resolve(name, "Properties.Name")
	is_string(n)
	some other in resources_of_type("AWS::VpcLattice::ServiceNetwork")
	other < name
	resolve(other, "Properties.Name") == n
}
