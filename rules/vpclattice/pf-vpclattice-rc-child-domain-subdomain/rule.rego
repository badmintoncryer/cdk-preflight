package cdk_preflight

import rego.v1

# When the GROUP has a GroupDomain, each CHILD's CustomDomainName must be a
# subdomain of it ("`db.other.example.net` is not a subdomain of domain
# `...`"). Checked when the CHILD names a GROUP in the same template and both
# domains are literal.
violation contains make_diag_full("pf-vpclattice-rc-child-domain-subdomain", "ERROR", name,
	"Properties.CustomDomainName",
	sprintf("CustomDomainName '%s' is not under the group domain '%s' of '%s'; the create fails with \"is not a subdomain of domain\"", [cd, gd, g]),
	"Use a name under the GROUP's GroupDomain (for example db.<group domain>)",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-configuration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	resolve(name, "Properties.ResourceConfigurationType") == "CHILD"
	g := resolve(name, "Properties.ResourceConfigurationGroupId")
	g in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	gd := lower(resolve(g, "Properties.GroupDomain"))
	cd := lower(resolve(name, "Properties.CustomDomainName"))
	cd != gd
	not endswith(cd, concat("", [".", gd]))
}
