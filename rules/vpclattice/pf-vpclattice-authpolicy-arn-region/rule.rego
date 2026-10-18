package cdk_preflight

import rego.v1

# The identifier pattern accepts an ARN of any region; the service rejects one
# outside its own region ("Provided ARN is either not valid or from a different region then this service.").
# data.cdk_preflight.deploy_region is defined only in enforce mode with a
# concrete region, otherwise this rule skips. Literal ARNs only.
violation contains make_diag_full("pf-vpclattice-authpolicy-arn-region", "ERROR", name,
	"Properties.ResourceIdentifier",
	sprintf("The ARN is in '%s' but the stack deploys to '%s'; the create fails with \"from a different region then this service\"", [r, region]),
	"Reference a resource in the deploy region",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_PutAuthPolicy.html") if {
	some name in resources_of_type("AWS::VpcLattice::AuthPolicy")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	p := _pf_vpcl_arn(resolve(name, "Properties.ResourceIdentifier"))
	p[2] == "vpc-lattice"
	r := p[3]
	r != region
}
