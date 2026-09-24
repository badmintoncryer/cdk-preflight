package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-schedule-expression-cron-only", "ERROR", name,
	sprintf("Properties.BackupPlan.BackupPlanRule.%d.ScheduleExpression", [r.index]),
	sprintf("ScheduleExpression must be a cron() expression, got %v: AWS Backup rejects rate() expressions", [s]),
	"Express the schedule as cron(), e.g. cron(0 5 ? * * *) instead of rate(1 day)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupplan-backupruleresourcetype.html") if {
	some name in resources_of_type("AWS::Backup::BackupPlan")
	some r in _pf_bklib_plan_rules(name)
	s := _pf_bklib_str(r.value, "ScheduleExpression")
	not startswith(s, "cron(")
}
