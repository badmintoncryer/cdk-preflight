package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-ws-am-root-route-receiver", "ERROR", name,
	"Properties.AlertManagerDefinition",
	"the root route has no receiver:; the definition ends in CREATION_FAILED with \"error validating Alertmanager config: root route must specify a default receiver\" and the stack rolls back",
	"Add receiver: <name of a declared receiver> to the root route",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-alertmanager-config.html") if {
	some name in resources_of_type("AWS::APS::Workspace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.AlertManagerDefinition"))
	some r in lines
	r.key == "route"
	not r.dash
	not "receiver" in _pf_aps_yaml_block_keys(lines, r)
}
