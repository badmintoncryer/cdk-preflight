package cdk_preflight

import rego.v1

# CONTINUE_DEPLOYMENT means "reroute as soon as the green fleet is ready", so
# there is no timeout to wait out. Zero is accepted (it is the same as no wait);
# anything above it is refused.
violation contains make_diag_full("pf-codedeploy-dg-deployment-ready-continue-no-wait-time", "ERROR", name,
	"Properties.BlueGreenDeploymentConfiguration.DeploymentReadyOption.WaitTimeInMinutes",
	sprintf("DeploymentReadyOption.ActionOnTimeout is CONTINUE_DEPLOYMENT with WaitTimeInMinutes %v; the deployment group create fails with \"Deployment ready action cannot be set to 'CONTINUE_DEPLOYMENT' when timeout is specified\"", [w]),
	"Drop WaitTimeInMinutes (or set it to 0), or use ActionOnTimeout STOP_DEPLOYMENT",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-deploymentreadyoption.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	bg := _pf_codedeploylib_obj(_pf_codedeploylib_props(name), "BlueGreenDeploymentConfiguration")
	dro := _pf_codedeploylib_obj(bg, "DeploymentReadyOption")
	object.get(dro, "ActionOnTimeout", null) == "CONTINUE_DEPLOYMENT"
	w := _pf_codedeploylib_num(object.get(dro, "WaitTimeInMinutes", null))
	w > 0
}
