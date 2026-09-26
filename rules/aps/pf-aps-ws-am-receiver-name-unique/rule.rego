package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-ws-am-receiver-name-unique", "ERROR", name,
	"Properties.AlertManagerDefinition",
	sprintf("two receivers are both named %v; the definition ends in CREATION_FAILED with \"error validating Alertmanager config: notification config name \"%v\" is not unique\" and the stack rolls back", [names[i], names[i]]),
	"Give each receiver a distinct name",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-alertmanager-config.html") if {
	some name in resources_of_type("AWS::APS::Workspace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.AlertManagerDefinition"))
	names := [v |
		some l in lines
		l.dash
		_pf_aps_yaml_parent(lines, l) == "receivers"
		some v in _pf_aps_values(_pf_aps_yaml_item(lines, l), "name")
		v != ""
	]
	some i, j
	i < j
	names[i] == names[j]
}
