package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-ws-am-receiver-type", "ERROR", name,
	"Properties.AlertManagerDefinition",
	sprintf("the Alertmanager definition uses %v; CreateWorkspace fails with \"Invalid Alertmanager receiver type: [%v]\"", [l.key, l.key]),
	"Amazon Managed Service for Prometheus routes alerts through Amazon SNS only: use sns_configs",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-alertmanager-config.html") if {
	some name in resources_of_type("AWS::APS::Workspace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.AlertManagerDefinition"))
	some l in lines
	regex.match(`^[a-z0-9_]+_configs$`, l.key)
	l.key != "sns_configs"
}
