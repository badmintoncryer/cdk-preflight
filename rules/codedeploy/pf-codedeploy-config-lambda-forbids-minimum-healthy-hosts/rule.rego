package cdk_preflight

import rego.v1

# MinimumHealthyHosts counts instances, which the Lambda and ECS platforms do
# not have. Both reject it; the message names the platform.
violation contains make_diag_full("pf-codedeploy-config-lambda-forbids-minimum-healthy-hosts", "ERROR", name,
	"Properties.MinimumHealthyHosts",
	sprintf("MinimumHealthyHosts is set on a %v deployment configuration; the create fails with \"minimum healthy hosts should be null for %v deployment configuration\"", [p, p]),
	"Drop MinimumHealthyHosts - only the Server (EC2/on-premises) platform takes it; Lambda and ECS use TrafficRoutingConfig",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codedeploy-deploymentconfig.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	p := _pf_codedeploylib_platform(name)
	p in {"Lambda", "ECS"}
	_pf_codedeploylib_has(_pf_codedeploylib_props(name), "MinimumHealthyHosts")
}
