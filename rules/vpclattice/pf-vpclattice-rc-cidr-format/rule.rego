package cdk_preflight

import rego.v1

# The schema checks only the length of each CidrRanges entry. An IPv4 CIDR with
# a prefix over 32 is rejected ("Invalid CIDR format: 172.31.0.0/33"). Other
# malformed strings and IPv6 ranges are not checked.
violation contains make_diag_full("pf-vpclattice-rc-cidr-format", "ERROR", name,
	sprintf("Properties.ResourceConfigurationDefinition.CidrResource.CidrRanges.%d", [it.index]),
	sprintf("CIDR '%s' has a prefix over 32; the create fails with \"Invalid CIDR format: %s\"", [s, s]),
	"Use an IPv4 CIDR with a prefix length from 0 to 32",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-configuration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	some it in flatten_list(name, "Properties.ResourceConfigurationDefinition.CidrResource.CidrRanges")
	s := it.value
	is_string(s)
	regex.match(`^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]+$`, s)
	to_number(split(s, "/")[1]) > 32
}
