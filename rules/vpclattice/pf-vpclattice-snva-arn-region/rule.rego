package cdk_preflight

import rego.v1

# The identifier pattern accepts an ARN of any region; the service rejects one
# outside its own region ("Invalid region in the serviceNetworkIdentifier provided. Must match current region us-east-1.").
# data.cdk_preflight.deploy_region is defined only in enforce mode with a
# concrete region, otherwise this rule skips. Literal ARNs only.
violation contains make_diag_full("pf-vpclattice-snva-arn-region", "ERROR", name,
	"Properties.ServiceNetworkIdentifier",
	sprintf("The ARN is in '%s' but the stack deploys to '%s'; the create fails with \"Invalid region in the serviceNetworkIdentifier provided\"", [r, region]),
	"Reference a resource in the deploy region",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateServiceNetworkVpcAssociation.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkVpcAssociation")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	p := _pf_vpcl_arn(resolve(name, "Properties.ServiceNetworkIdentifier"))
	p[2] == "vpc-lattice"
	r := p[3]
	r != region
}
