package cdk_preflight

import rego.v1

# STOP_DEPLOYMENT stops the deployment when the timeout expires, so a timeout of
# zero (written, or left out and defaulted) would stop it before it began.
_pf_cdstop_wait(dro) := w if {
	w := _pf_codedeploylib_num(object.get(dro, "WaitTimeInMinutes", null))
}

_pf_cdstop_wait(dro) := 0 if {
	not _pf_codedeploylib_has(dro, "WaitTimeInMinutes")
}

violation contains make_diag_full("pf-codedeploy-dg-deployment-ready-stop-requires-wait-time", "ERROR", name,
	"Properties.BlueGreenDeploymentConfiguration.DeploymentReadyOption.WaitTimeInMinutes",
	"DeploymentReadyOption.ActionOnTimeout is STOP_DEPLOYMENT with a wait time of 0 minutes; the deployment group create fails with \"Deployment ready action cannot be set to STOP_DEPLOYMENT when timeout is set to 0 minutes.\"",
	"Set WaitTimeInMinutes to the number of minutes to wait before stopping, or use ActionOnTimeout CONTINUE_DEPLOYMENT",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-deploymentreadyoption.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	bg := _pf_codedeploylib_obj(_pf_codedeploylib_props(name), "BlueGreenDeploymentConfiguration")
	dro := _pf_codedeploylib_obj(bg, "DeploymentReadyOption")
	object.get(dro, "ActionOnTimeout", null) == "STOP_DEPLOYMENT"
	_pf_cdstop_wait(dro) == 0
}
