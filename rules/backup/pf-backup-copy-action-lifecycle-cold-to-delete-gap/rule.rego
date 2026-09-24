package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-copy-action-lifecycle-cold-to-delete-gap", "ERROR", name,
	sprintf("Properties.BackupPlan.BackupPlanRule.%d.CopyActions.%d.Lifecycle.DeleteAfterDays", [r.index, a.index]),
	sprintf("DeleteAfterDays (%v) must be at least 90 days after MoveToColdStorageAfterDays (%v): the 90-day cold storage minimum applies to copy actions too", [d, c]),
	"Set DeleteAfterDays to MoveToColdStorageAfterDays + 90 or more, or drop MoveToColdStorageAfterDays from the copy action",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupplan-copyactionresourcetype.html") if {
	some name in resources_of_type("AWS::Backup::BackupPlan")
	some r in _pf_bklib_plan_rules(name)
	some a in _pf_bklib_copy_actions(name, r.index)
	lc := _pf_bklib_lifecycle(a.value)
	c := _pf_bklib_num(lc, "MoveToColdStorageAfterDays")
	d := _pf_bklib_num(lc, "DeleteAfterDays")
	d < c + 90
}
