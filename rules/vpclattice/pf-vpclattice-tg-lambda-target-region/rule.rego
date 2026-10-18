package cdk_preflight

import rego.v1

# A Lambda target must live in the target group region; RegisterTargets
# rejects a function ARN of another region ("LAMBDA target id: arn:aws:lambda:
# ap-northeast-1:...:function:... failed validation"). data.cdk_preflight.
# deploy_region is defined only in enforce mode with a concrete region,
# otherwise this rule skips.
violation contains make_diag_full("pf-vpclattice-tg-lambda-target-region", "ERROR", name,
	sprintf("Properties.Targets.%d.Id", [t.index]),
	sprintf("The function lives in '%s' but the stack deploys to '%s'; RegisterTargets fails with \"LAMBDA target id: ... failed validation\"", [r, region]),
	"Register a function in the deploy region",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/lambda-functions.html") if {
	some name in _pf_vpcl_tgs_of("LAMBDA")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	some t in flatten_list(name, "Properties.Targets")
	p := _pf_vpcl_arn(_pf_vpcl_target_id(t))
	p[2] == "lambda"
	r := p[3]
	r != region
}
