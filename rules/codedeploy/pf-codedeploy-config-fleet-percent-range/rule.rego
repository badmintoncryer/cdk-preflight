package cdk_preflight

import rego.v1

# 100% healthy would leave nothing to deploy to, so the ceiling is exclusive.
# There is no floor: 0 is accepted despite the "should be positive" wording.
violation contains make_diag_full("pf-codedeploy-config-fleet-percent-range", "ERROR", name,
	"Properties.MinimumHealthyHosts.Value",
	sprintf("MinimumHealthyHosts is FLEET_PERCENT %v; the deployment configuration create fails with \"The value for the minimum healthy hosts with type of FLEET_PERCENT should be positive and less than 100\"", [v]),
	"Use a FLEET_PERCENT value of 99 or less, or switch Type to HOST_COUNT",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentconfig-minimumhealthyhosts.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	resolve(name, "Properties.MinimumHealthyHosts.Type") == "FLEET_PERCENT"
	v := _pf_codedeploylib_num(resolve(name, "Properties.MinimumHealthyHosts.Value"))
	v > 99
}
