package cdk_preflight

import rego.v1

# A Lambda deployment group is always blue/green, and the shift is described by
# its deployment configuration rather than by this block, which talks about
# instances and Auto Scaling groups. ECS is the opposite - there the block is
# mandatory - so this one names Lambda only.
violation contains make_diag_full("pf-codedeploy-dg-lambda-forbids-blue-green-config", "ERROR", name,
	"Properties.BlueGreenDeploymentConfiguration",
	"BlueGreenDeploymentConfiguration is set on a deployment group whose application is the Lambda compute platform; the create fails with \"For Lambda deployment group, blueGreenDeploymentConfiguration can not be specified\"",
	"Drop BlueGreenDeploymentConfiguration - a Lambda deployment group shifts traffic through its DeploymentConfigName",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-bluegreendeploymentconfiguration.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	_pf_codedeploylib_dg_platform(name) == "Lambda"
	_pf_codedeploylib_has(_pf_codedeploylib_props(name), "BlueGreenDeploymentConfiguration")
}
