package cdk_preflight

import rego.v1

# Enabled with no Events is a rollback that can never trigger, and the service
# refuses it rather than picking a default.
_pf_cdroll_one(rc) if {
	e := object.get(rc, "Events", null)
	is_array(e)
	_pf_unconditional_items(e)
	count(e) > 0
}

_pf_cdroll_one(rc) if {
	e := object.get(rc, "Events", null)
	e != null
	not is_array(e)
}

violation contains make_diag_full("pf-codedeploy-dg-autorollback-enabled-requires-events", "ERROR", name,
	"Properties.AutoRollbackConfiguration.Events",
	"AutoRollbackConfiguration.Enabled is true but no event is listed; the deployment group create fails with \"Deployment Groups need to have at least one event specified when auto rollback is enabled\"",
	"List at least one event (DEPLOYMENT_FAILURE, DEPLOYMENT_STOP_ON_ALARM, DEPLOYMENT_STOP_ON_REQUEST), or set Enabled to false",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-autorollbackconfiguration.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	rc := _pf_codedeploylib_obj(_pf_codedeploylib_props(name), "AutoRollbackConfiguration")
	object.get(rc, "Enabled", false) == true
	not _pf_cdroll_one(rc)
}
