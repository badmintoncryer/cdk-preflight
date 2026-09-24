package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-restore-testing-selection-arns-xor-conditions", "ERROR", name,
	"Properties.ProtectedResourceArns",
	"ProtectedResourceArns and ProtectedResourceConditions are mutually exclusive: a selection either names resources or matches them by tag",
	"Keep ProtectedResourceArns (an explicit list) or ProtectedResourceConditions (tag matching), not both",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-backup-restoretestingselection.html") if {
	some name in resources_of_type("AWS::Backup::RestoreTestingSelection")
	p := _pf_bklib_props(name)
	arns := _pf_bklib_get(p, "ProtectedResourceArns")
	is_array(arns)
	count(arns) > 0
	conds := _pf_bklib_get(p, "ProtectedResourceConditions")
	is_object(conds)
	count(conds) > 0
}
