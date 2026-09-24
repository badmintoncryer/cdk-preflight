package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-restore-testing-plan-recovery-point-types", "ERROR", name,
	sprintf("Properties.RecoveryPointSelection.RecoveryPointTypes.%d", [t.index]),
	sprintf("RecoveryPointTypes entry %v is not one of SNAPSHOT or CONTINUOUS", [t.value]),
	"Use SNAPSHOT (periodic backups) or CONTINUOUS (point-in-time recovery)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-restoretestingplan-restoretestingrecoverypointselection.html") if {
	some name in resources_of_type("AWS::Backup::RestoreTestingPlan")
	some t in flatten_list(name, "Properties.RecoveryPointSelection.RecoveryPointTypes")
	is_string(t.value)
	not t.value in {"SNAPSHOT", "CONTINUOUS"}
}
