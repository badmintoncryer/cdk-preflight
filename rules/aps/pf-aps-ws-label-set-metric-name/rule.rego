package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-ws-label-set-metric-name", "ERROR", name,
	"Properties.WorkspaceConfiguration.LimitsPerLabelSets",
	sprintf("the __name__ label limit is %v; UpdateWorkspaceConfiguration fails with \"__name__ label value must satisfy regular expression pattern [a-zA-Z_:][a-zA-Z0-9_:]*\"", [v]),
	"Use a metric name of letters, digits, underscores and colons (no hyphens)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-aps-workspace-limitsperlabelset.html") if {
	some name in resources_of_type("AWS::APS::Workspace")
	some labels in _pf_aps_label_sets(name)
	some label in labels
	is_object(label)
	object.get(label, "Name", "") == "__name__"
	v := object.get(label, "Value", "")
	is_string(v)
	not regex.match(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`, v)
}
