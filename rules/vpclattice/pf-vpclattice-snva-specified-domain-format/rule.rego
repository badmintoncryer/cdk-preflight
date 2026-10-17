package cdk_preflight

import rego.v1

# The schema checks only the length of each domain. A domain with a space or a
# non-ASCII character is rejected ("Domain api example.com has invalid
# format"). The full host-name grammar is not checked.
violation contains make_diag_full("pf-vpclattice-snva-specified-domain-format", "ERROR", name,
	sprintf("Properties.DnsOptions.PrivateDnsSpecifiedDomains.%d", [it.index]),
	sprintf("Domain '%s' contains a space or a non-ASCII character; the create fails with \"Domain ... has invalid format\"", [it.value]),
	"Remove spaces and write an internationalized name in punycode (xn--...)",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_DnsOptions.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkVpcAssociation")
	some it in flatten_list(name, "Properties.DnsOptions.PrivateDnsSpecifiedDomains")
	_pf_vpcl_bad_domain(it.value)
}
