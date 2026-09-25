package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-topicrule-role-account", "ERROR", name,
	sprintf("Properties.TopicRulePayload.Actions.%d.%s.RoleArn", [i, k]),
	sprintf("the action's RoleArn names a role in account '%s' but the stack deploys to '%s'; IoT will not pass a role across accounts - CreateTopicRule answers \"Cross-account pass role is not allowed.\" and the stack event collapses it to \"Access denied for operation 'CreateTopicRule'.\"", [roleAccount, account]),
	"Reference a role in the deploy account",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-topicrule.html") if {
	some [name, i, a] in _pf_iotlib_action
	account := data.cdk_preflight.deploy_account
	is_string(account)
	some k in object.keys(a)
	arn := object.get(object.get(a, k, {}), "RoleArn", null)
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "iam"
	roleAccount := parts[4]
	roleAccount != ""
	roleAccount != account
}
