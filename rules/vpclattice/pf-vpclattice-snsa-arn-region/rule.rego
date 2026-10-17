package cdk_preflight

import rego.v1

# The identifier patterns accept an ARN of any region; the service rejects one
# outside its own region ("Provided ARN is either not valid or from a different region then this service.").
# data.cdk_preflight.deploy_region is defined only in enforce mode with a
# concrete region, otherwise this rule skips. Literal ARNs only.
# Only ServiceNetworkIdentifier is checked: a missing service network of the
# same region gives "cannot be found" instead, so this text tracks the region.
# A service ARN of another region returns the same text, but no same-region
# baseline separates it from a plain not-found, so ServiceIdentifier is left out.
violation contains make_diag_full("pf-vpclattice-snsa-arn-region", "ERROR", name,
	"Properties.ServiceNetworkIdentifier",
	sprintf("The ARN is in '%s' but the stack deploys to '%s'; the create fails with \"from a different region then this service\"", [r, region]),
	"Reference a resource in the deploy region",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateServiceNetworkServiceAssociation.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkServiceAssociation")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	v := resolve(name, "Properties.ServiceNetworkIdentifier")
	p := _pf_vpcl_arn(v)
	p[2] == "vpc-lattice"
	r := p[3]
	r != region
}
