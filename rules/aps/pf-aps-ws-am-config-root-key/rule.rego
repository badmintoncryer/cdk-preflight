package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-ws-am-config-root-key", "ERROR", name,
	"Properties.AlertManagerDefinition",
	"the Alertmanager definition has no alertmanager_config key at the root; CreateWorkspace fails with \"Empty Alertmanager definition.\"",
	"Wrap the whole configuration in a top-level alertmanager_config: | block",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-alertmanager-config.html") if {
	some name in resources_of_type("AWS::APS::Workspace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.AlertManagerDefinition"))
	count(lines) > 0
	roots := {l.key | some l in lines; l.indent == 0}
	not "alertmanager_config" in roots
}
