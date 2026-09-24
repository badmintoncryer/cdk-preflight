package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-lifecycle-cold-to-delete-gap", "ERROR", name,
	sprintf("Properties.BackupPlan.BackupPlanRule.%d.Lifecycle.DeleteAfterDays", [r.index]),
	sprintf("DeleteAfterDays (%v) must be at least 90 days after MoveToColdStorageAfterDays (%v): cold storage has a 90-day minimum retention", [d, c]),
	"Set DeleteAfterDays to MoveToColdStorageAfterDays + 90 or more, or drop MoveToColdStorageAfterDays",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupplan-lifecycleresourcetype.html") if {
	some name in resources_of_type("AWS::Backup::BackupPlan")
	some r in _pf_bklib_plan_rules(name)
	lc := _pf_bklib_lifecycle(r.value)
	c := _pf_bklib_num(lc, "MoveToColdStorageAfterDays")
	d := _pf_bklib_num(lc, "DeleteAfterDays")
	d < c + 90
}
