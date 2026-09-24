package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-framework-control-scope-tags-max-one", "ERROR", name,
	sprintf("Properties.FrameworkControls.%d.ControlScope.Tags", [c.index]),
	sprintf("ControlScope.Tags carries %d tag pairs; a control scope accepts at most one key/value pair", [count(tags)]),
	"Keep a single tag pair in ControlScope.Tags (use ComplianceResourceTypes to widen the scope instead)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-framework-controlscope.html") if {
	some name in resources_of_type("AWS::Backup::Framework")
	some c in flatten_list(name, "Properties.FrameworkControls")
	scope := _pf_bklib_get(c.value, "ControlScope")
	tags := _pf_bklib_get(scope, "Tags")
	is_array(tags)
	count(tags) > 1
}
