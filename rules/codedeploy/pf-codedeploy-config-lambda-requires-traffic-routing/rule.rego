package cdk_preflight

import rego.v1

# The Lambda and ECS platforms shift traffic rather than count healthy hosts, so
# the routing block is the whole configuration and the service has no default.
violation contains make_diag_full("pf-codedeploy-config-lambda-requires-traffic-routing", "ERROR", name,
	"Properties.TrafficRoutingConfig",
	sprintf("A %v deployment configuration has no TrafficRoutingConfig; the create fails with \"Traffic routing configuration cannot be null nor empty for deployment configurations on this platform.\"", [p]),
	"Add TrafficRoutingConfig with a Type (AllAtOnce, TimeBasedCanary or TimeBasedLinear)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codedeploy-deploymentconfig.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	p := _pf_codedeploylib_platform(name)
	p in {"Lambda", "ECS"}
	not _pf_codedeploylib_has(_pf_codedeploylib_props(name), "TrafficRoutingConfig")
}
