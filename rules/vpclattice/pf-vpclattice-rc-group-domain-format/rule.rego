package cdk_preflight

import rego.v1

# The schema bounds only the length of GroupDomain. CreateResourceConfiguration
# rejects a space or any non-ASCII character ("`api example.com` is not a valid
# resource configuration domain name"). Other hostname rules are not checked.
violation contains make_diag_full("pf-vpclattice-rc-group-domain-format", "ERROR", name,
	"Properties.GroupDomain",
	sprintf("GroupDomain '%s' has a space or a non-ASCII character; the create fails with \"is not a valid resource configuration domain name\"", [d]),
	"Remove spaces and write an internationalized name in punycode (xn--...)",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	d := resolve(name, "Properties.GroupDomain")
	_pf_vpcl_bad_domain(d)
}
