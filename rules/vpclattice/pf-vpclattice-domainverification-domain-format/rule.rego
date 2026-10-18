package cdk_preflight

import rego.v1

# The schema bounds only the length of DomainName. StartDomainVerification rejects a
# space or any non-ASCII character ("Domain names must contain only ASCII
# characters: api example.com. For international domain names, please conert to
# punycode format"). Other hostname rules (label length, underscores) are not
# checked.
violation contains make_diag_full("pf-vpclattice-domainverification-domain-format", "ERROR", name,
	"Properties.DomainName",
	sprintf("Domain name '%s' has a space or a non-ASCII character; StartDomainVerification fails with \"Domain names must contain only ASCII characters\"", [d]),
	"Remove spaces and write an internationalized name in punycode (xn--...)",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_StartDomainVerification.html") if {
	some name in resources_of_type("AWS::VpcLattice::DomainVerification")
	d := resolve(name, "Properties.DomainName")
	_pf_vpcl_bad_domain(d)
}
