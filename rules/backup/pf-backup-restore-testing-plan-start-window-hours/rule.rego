package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-restore-testing-plan-start-window-hours", "ERROR", name,
	"Properties.StartWindowHours",
	sprintf("StartWindowHours %v is above the 168-hour (one week) maximum", [h]),
	"Use a StartWindowHours of 168 or less",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-backup-restoretestingplan.html") if {
	some name in resources_of_type("AWS::Backup::RestoreTestingPlan")
	h := _pf_bklib_num(_pf_bklib_props(name), "StartWindowHours")
	h > 168
}
