package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-restore-testing-plan-include-vaults-required", "ERROR", name,
	"Properties.RecoveryPointSelection.IncludeVaults",
	"IncludeVaults is empty: a restore testing plan must name the vaults (or \"*\") it draws recovery points from",
	"List at least one vault ARN in IncludeVaults, or use [\"*\"] for every vault",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-restoretestingplan-restoretestingrecoverypointselection.html") if {
	some name in resources_of_type("AWS::Backup::RestoreTestingPlan")
	sel := _pf_bklib_get(_pf_bklib_props(name), "RecoveryPointSelection")
	v := object.get(sel, "IncludeVaults", [])
	is_array(v)
	count(v) < 1
}
