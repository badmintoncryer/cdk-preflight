package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-continuous-no-cold-storage", "ERROR", name,
	sprintf("Properties.BackupPlan.BackupPlanRule.%d.Lifecycle.MoveToColdStorageAfterDays", [r.index]),
	sprintf("EnableContinuousBackup: true cannot be combined with MoveToColdStorageAfterDays (%v): continuous backups keep at most 35 days and cold storage has a 90-day minimum", [c]),
	"Drop MoveToColdStorageAfterDays from the continuous backup rule (or drop EnableContinuousBackup)",
	"https://docs.aws.amazon.com/aws-backup/latest/devguide/point-in-time-recovery.html") if {
	some name in resources_of_type("AWS::Backup::BackupPlan")
	some r in _pf_bklib_plan_rules(name)
	_pf_bklib_get(r.value, "EnableContinuousBackup") == true
	lc := _pf_bklib_lifecycle(r.value)
	c := _pf_bklib_num(lc, "MoveToColdStorageAfterDays")
}
