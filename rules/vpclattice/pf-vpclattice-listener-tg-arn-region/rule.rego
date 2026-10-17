package cdk_preflight

import rego.v1

# The identifier patterns accept an ARN of any region; the service rejects one
# outside its own region ("Invalid region in the targetGroupIdentifier provided. Must match current region us-east-1.").
# data.cdk_preflight.deploy_region is defined only in enforce mode with a
# concrete region, otherwise this rule skips. Literal ARNs only.
violation contains make_diag_full("pf-vpclattice-listener-tg-arn-region", "ERROR", name,
	sprintf("Properties.DefaultAction.Forward.TargetGroups.%d.TargetGroupIdentifier", [it.index]),
	sprintf("The ARN is in '%s' but the stack deploys to '%s'; the create fails with \"Invalid region in the targetGroupIdentifier provided\"", [r, region]),
	"Reference a resource in the deploy region",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_WeightedTargetGroup.html") if {
	some name in resources_of_type("AWS::VpcLattice::Listener")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	some it in flatten_list(name, "Properties.DefaultAction.Forward.TargetGroups")
	v := resolve(name, sprintf("Properties.DefaultAction.Forward.TargetGroups.%d.TargetGroupIdentifier", [it.index]))
	p := _pf_vpcl_arn(v)
	p[2] == "vpc-lattice"
	r := p[3]
	r != region
}
