package cdk_preflight

import rego.v1

# An in-place EC2/on-premises deployment has no traffic to shift. An absent
# ComputePlatform is Server, so the same rejection applies to a configuration
# that never names a platform.
violation contains make_diag_full("pf-codedeploy-config-server-forbids-traffic-routing", "ERROR", name,
	"Properties.TrafficRoutingConfig",
	"TrafficRoutingConfig is set on a Server deployment configuration; the create fails with \"Traffic routing configuration should be null for Server deployment configuration\"",
	"Drop TrafficRoutingConfig, or set ComputePlatform to Lambda or ECS (an absent ComputePlatform is Server)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codedeploy-deploymentconfig.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	_pf_codedeploylib_platform(name) == "Server"
	_pf_codedeploylib_has(_pf_codedeploylib_props(name), "TrafficRoutingConfig")
}
