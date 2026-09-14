package cdk_preflight

import rego.v1

# An EC2/on-premises deployment group has no ECS services to name.
# TargetGroupPairInfoList is in the same sentence of the service error but is NOT
# in the same check: the service accepts it on a Server group (measured
# 2026-09-14 us-east-1), so this rule does not claim it.
violation contains make_diag_full("pf-codedeploy-dg-ecs-services-requires-ecs-platform", "ERROR", name,
	"Properties.ECSServices",
	"ECSServices is set on a deployment group whose application is the Server compute platform; the create fails with \"Server Deployment Groups should not define a value for ecsServices, eksClusters, or targetGroupPairInfoList\"",
	"Drop ECSServices, or point ApplicationName at an application whose ComputePlatform is ECS",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codedeploy-deploymentgroup.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	_pf_codedeploylib_dg_platform(name) == "Server"
	_pf_codedeploylib_has(_pf_codedeploylib_props(name), "ECSServices")
}
