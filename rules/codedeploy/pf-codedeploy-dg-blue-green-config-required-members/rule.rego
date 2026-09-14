package cdk_preflight

import rego.v1

# Both members are optional in the schema and neither gets a default: writing the
# block at all commits you to both. The trigger is the block, not DeploymentStyle -
# the service refuses these on a group that never says BLUE_GREEN (measured
# 2026-09-14 us-east-1), which is also why the candidate's "a BLUE_GREEN deployment
# group must set ..." wording is narrower than the check.
violation contains make_diag_full("pf-codedeploy-dg-blue-green-config-required-members", "ERROR", name,
	"Properties.BlueGreenDeploymentConfiguration.DeploymentReadyOption",
	"BlueGreenDeploymentConfiguration has no DeploymentReadyOption; the deployment group create fails with \"Deployment ready option cannot be null for blue green deployment\"",
	"Add DeploymentReadyOption with an ActionOnTimeout, or drop BlueGreenDeploymentConfiguration",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-bluegreendeploymentconfiguration.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	bg := _pf_codedeploylib_obj(_pf_codedeploylib_props(name), "BlueGreenDeploymentConfiguration")
	not _pf_codedeploylib_has(bg, "DeploymentReadyOption")
}

violation contains make_diag_full("pf-codedeploy-dg-blue-green-config-required-members", "ERROR", name,
	"Properties.BlueGreenDeploymentConfiguration.TerminateBlueInstancesOnDeploymentSuccess",
	"BlueGreenDeploymentConfiguration has no TerminateBlueInstancesOnDeploymentSuccess; the deployment group create fails with \"Terminate blue instances on deployment success behaviour cannot be set to null for Blue Green deployments\"",
	"Add TerminateBlueInstancesOnDeploymentSuccess with an Action (TERMINATE or KEEP_ALIVE)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-bluegreendeploymentconfiguration.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	bg := _pf_codedeploylib_obj(_pf_codedeploylib_props(name), "BlueGreenDeploymentConfiguration")
	not _pf_codedeploylib_has(bg, "TerminateBlueInstancesOnDeploymentSuccess")
}
