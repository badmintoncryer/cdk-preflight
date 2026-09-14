package cdk_preflight

import rego.v1

# Blue/green swaps traffic between two fleets, so there is no such thing as a
# blue/green deployment that does not reroute traffic. A Lambda group gets a
# different message for the same shape ("For LAMBDA deployment, ...") and is left
# to pf-codedeploy-dg-lambda-requires-blue-green-traffic-control; the guard is
# written as a negation so a group naming an application outside the template -
# where the platform is unknowable - is still checked.
_pf_cdbgtc_lambda(name) if {
	_pf_codedeploylib_dg_platform(name) == "Lambda"
}

violation contains make_diag_full("pf-codedeploy-dg-bluegreen-requires-traffic-control", "ERROR", name,
	"Properties.DeploymentStyle.DeploymentOption",
	"DeploymentStyle is BLUE_GREEN with WITHOUT_TRAFFIC_CONTROL; the deployment group create fails with \"BLUE_GREEN deployment type not supported with WITHOUT_TRAFFIC_CONTROL option\"",
	"Set DeploymentOption to WITH_TRAFFIC_CONTROL (and give the group a LoadBalancerInfo), or use DeploymentType IN_PLACE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-deploymentstyle.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	not _pf_cdbgtc_lambda(name)
	ds := _pf_codedeploylib_obj(_pf_codedeploylib_props(name), "DeploymentStyle")
	object.get(ds, "DeploymentType", null) == "BLUE_GREEN"
	object.get(ds, "DeploymentOption", null) == "WITHOUT_TRAFFIC_CONTROL"
}
