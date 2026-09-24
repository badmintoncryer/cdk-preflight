package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-restore-testing-plan-selection-window-days", "ERROR", name,
	"Properties.RecoveryPointSelection.SelectionWindowDays",
	sprintf("SelectionWindowDays %v is above the 365-day maximum", [d]),
	"Use a SelectionWindowDays of 365 or less",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-restoretestingplan-restoretestingrecoverypointselection.html") if {
	some name in resources_of_type("AWS::Backup::RestoreTestingPlan")
	sel := _pf_bklib_get(_pf_bklib_props(name), "RecoveryPointSelection")
	d := _pf_bklib_num(sel, "SelectionWindowDays")
	d > 365
}
