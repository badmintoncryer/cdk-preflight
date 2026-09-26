package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-ws-am-route-receiver-defined", "ERROR", name,
	"Properties.AlertManagerDefinition",
	sprintf("route sends to receiver %v, which no receivers: item declares; the definition ends in CREATION_FAILED with \"error validating Alertmanager config: undefined receiver \"%v\" used in route\" and the stack rolls back", [l.value, l.value]),
	"Name a receiver that receivers: declares (spelling included)",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-alertmanager-config.html") if {
	some name in resources_of_type("AWS::APS::Workspace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.AlertManagerDefinition"))
	declared := {l.value | some l in lines; l.key == "name"}
	some l in lines
	l.key == "receiver"
	l.value != ""
	not l.value in declared
}
