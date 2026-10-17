package cdk_preflight

import rego.v1

# Name is not the primary identifier, so the schema says nothing about
# uniqueness, but CreateResourceConfiguration fails for a name already taken in
# the account and region ("RESOURCE_CONFIGURATION with name ... already
# exists"). Only names inside one template are compared, as written.
violation contains make_diag_full("pf-vpclattice-resourceconfiguration-name-duplicate", "ERROR", name,
	"Properties.Name",
	sprintf("Resource configuration name '%s' is already used by resource '%s'; the create fails with \"RESOURCE_CONFIGURATION with name %s already exists\"", [n, other, n]),
	"Give each resource configuration its own Name",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	n := resolve(name, "Properties.Name")
	is_string(n)
	some other in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	other < name
	resolve(other, "Properties.Name") == n
}
