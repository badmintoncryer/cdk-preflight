package cdk_preflight

import rego.v1

# Enabled means "gate the deployment on these alarms", so the list has to name
# one. An absent list and an empty list are both refused, with two messages.
_pf_cdalarm_one(ac) if {
	a := object.get(ac, "Alarms", null)
	is_array(a)
	_pf_unconditional_items(a)
	count(a) > 0
}

# A token in place of the list: unknowable, so the rule stays quiet.
_pf_cdalarm_one(ac) if {
	a := object.get(ac, "Alarms", null)
	a != null
	not is_array(a)
}

violation contains make_diag_full("pf-codedeploy-dg-alarm-configuration-enabled-requires-alarms", "ERROR", name,
	"Properties.AlarmConfiguration.Alarms",
	"AlarmConfiguration.Enabled is true but no alarm is listed; the deployment group create fails with \"Deployment Groups need to have at least one alarms attached if they are monitored.\"",
	"List at least one CloudWatch alarm in AlarmConfiguration.Alarms, or set Enabled to false",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-alarmconfiguration.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	ac := _pf_codedeploylib_obj(_pf_codedeploylib_props(name), "AlarmConfiguration")
	object.get(ac, "Enabled", false) == true
	not _pf_cdalarm_one(ac)
}
