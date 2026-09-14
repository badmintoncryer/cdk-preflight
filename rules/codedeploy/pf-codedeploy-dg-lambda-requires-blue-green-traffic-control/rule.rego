package cdk_preflight

import rego.v1

# A Lambda deployment always shifts an alias between two versions, so it has
# exactly one legal deployment style. Only a written-out value is judged: an
# absent DeploymentStyle is left to CloudFormation's handler, which supplies one.
# That handler also sends ec2TagFilters for any DeploymentType other than
# BLUE_GREEN, so an IN_PLACE Lambda group is refused for the tag filters before
# the style is ever looked at (measured 2026-09-14 us-east-1) - the deploy still
# fails, just with the other sentence.
_pf_cdlbg_bad(ds) if {
	dt := object.get(ds, "DeploymentType", null)
	_pf_codedeploylib_lit(dt)
	dt != "BLUE_GREEN"
}

_pf_cdlbg_bad(ds) if {
	o := object.get(ds, "DeploymentOption", null)
	_pf_codedeploylib_lit(o)
	o != "WITH_TRAFFIC_CONTROL"
}

violation contains make_diag_full("pf-codedeploy-dg-lambda-requires-blue-green-traffic-control", "ERROR", name,
	"Properties.DeploymentStyle",
	"The application is the Lambda compute platform, so the deployment group create fails with \"For LAMBDA deployment, the deployment type must be BLUE_GREEN, and deployment option must be WITH_TRAFFIC_CONTROL.\"",
	"Set DeploymentStyle to DeploymentType BLUE_GREEN with DeploymentOption WITH_TRAFFIC_CONTROL",
	"https://docs.aws.amazon.com/codedeploy/latest/APIReference/API_CreateDeploymentGroup.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	_pf_codedeploylib_dg_platform(name) == "Lambda"
	ds := _pf_codedeploylib_obj(_pf_codedeploylib_props(name), "DeploymentStyle")
	_pf_cdlbg_bad(ds)
}
