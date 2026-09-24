package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-continuous-delete-after-days-max", "ERROR", name,
	sprintf("Properties.BackupPlan.BackupPlanRule.%d.Lifecycle.DeleteAfterDays", [r.index]),
	sprintf("EnableContinuousBackup: true caps DeleteAfterDays at 35 days, not %v (the service error misreports the ceiling as 36500)", [d]),
	"Set DeleteAfterDays to 35 or less on the continuous backup rule, or use a snapshot rule for longer retention",
	"https://docs.aws.amazon.com/aws-backup/latest/devguide/point-in-time-recovery.html") if {
	some name in resources_of_type("AWS::Backup::BackupPlan")
	some r in _pf_bklib_plan_rules(name)
	_pf_bklib_get(r.value, "EnableContinuousBackup") == true
	lc := _pf_bklib_lifecycle(r.value)
	d := _pf_bklib_num(lc, "DeleteAfterDays")
	d > 35
}
