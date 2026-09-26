package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-ws-am-sns-topic-account", "ERROR", name,
	"Properties.AlertManagerDefinition",
	sprintf("the SNS topic belongs to account %v but the workspace deploys into %v; CreateWorkspace fails with \"Invalid SNS receiver topic account ID: %v\"", [m[1], account, m[1]]),
	"Point sns_configs at a topic in the workspace's own account (${AWS::AccountId})",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-alertmanager-config.html") if {
	some name in resources_of_type("AWS::APS::Workspace")
	account := data.cdk_preflight.deploy_account
	is_string(account)
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.AlertManagerDefinition"))
	some l in lines
	l.key == "topic_arn"
	m := regex.find_all_string_submatch_n(`^arn:aws[a-z0-9-]*:sns:[a-z0-9-]+:([0-9]{12}):`, l.value, 1)[0]
	m[1] != account
}
