package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-restore-testing-plan-name-charset", "ERROR", name,
	"Properties.RestoreTestingPlanName",
	sprintf("RestoreTestingPlanName %v contains characters other than letters, digits and underscores (hyphens are rejected)", [n]),
	"Rename the plan without hyphens, e.g. my_restore_testing_plan (CDK default names contain hyphens, so pass an explicit name)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-backup-restoretestingplan.html") if {
	some name in resources_of_type("AWS::Backup::RestoreTestingPlan")
	n := _pf_bklib_str(_pf_bklib_props(name), "RestoreTestingPlanName")
	not _pf_bklib_underscore_name(n)
}
