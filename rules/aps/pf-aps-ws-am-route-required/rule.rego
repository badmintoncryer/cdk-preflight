package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-ws-am-route-required", "ERROR", name,
	"Properties.AlertManagerDefinition",
	"the Alertmanager definition has no route:; the definition ends in CREATION_FAILED with \"error validating Alertmanager config: no routes provided\" and the stack rolls back",
	"Give alertmanager_config a route: with a default receiver",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-alertmanager-config.html") if {
	some name in resources_of_type("AWS::APS::Workspace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.AlertManagerDefinition"))
	roots := {l.key | some l in lines; l.indent == 0}
	"alertmanager_config" in roots
	some nested in lines
	nested.indent > 0
	keys := {l.key | some l in lines}
	not "route" in keys
}
