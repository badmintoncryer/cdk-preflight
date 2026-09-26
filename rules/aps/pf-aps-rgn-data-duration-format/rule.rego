package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-rgn-data-duration-format", "ERROR", name,
	"Properties.Data",
	sprintf("%v: %v has no unit; CreateRuleGroupsNamespace fails with \"not a valid duration string: %v\"", [p[0], p[1], p[1]]),
	"Write the duration with a unit (30s, 5m, 1h30m); a bare zero is the only exception",
	"https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-Ruler-Config.html") if {
	some name in resources_of_type("AWS::APS::RuleGroupsNamespace")
	lines := _pf_aps_yaml_lines(_pf_aps_str(name, "Properties.Data"))
	some l in lines
	l.dash
	some p in _pf_aps_yaml_item(lines, l)
	p[0] in {"interval", "query_offset", "for", "keep_firing_for"}
	regex.match(`^[0-9]+$`, p[1])
	p[1] != "0"
}
