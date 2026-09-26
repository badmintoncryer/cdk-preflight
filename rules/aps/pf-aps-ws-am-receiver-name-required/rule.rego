package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-ws-am-receiver-name-required", "ERROR", name,
	"Properties.AlertManagerDefinition",
	"a receiver has no name:; the definition ends in CREATION_FAILED with \"error validating Alertmanager config: missing name in receiver\" and the stack rolls back",
	"Give every item under receivers: a name:",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-alertmanager-config.html") if {
	some name in resources_of_type("AWS::APS::Workspace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.AlertManagerDefinition"))
	some l in lines
	l.dash
	_pf_aps_yaml_parent(lines, l) == "receivers"
	names := {v | some v in _pf_aps_values(_pf_aps_yaml_item(lines, l), "name"); v != ""}
	names == set()
}
