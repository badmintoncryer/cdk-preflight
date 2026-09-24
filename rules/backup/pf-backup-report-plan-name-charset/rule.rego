package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-report-plan-name-charset", "ERROR", name,
	"Properties.ReportPlanName",
	sprintf("ReportPlanName %v must start with a letter and contain only letters, digits and underscores (hyphens are rejected)", [n]),
	"Rename the report plan without hyphens, e.g. my_report_plan (CDK default names contain hyphens, so pass an explicit reportPlanName)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-backup-reportplan.html") if {
	some name in resources_of_type("AWS::Backup::ReportPlan")
	n := _pf_bklib_str(_pf_bklib_props(name), "ReportPlanName")
	not regex.match(`^[A-Za-z][A-Za-z0-9_]*$`, n)
}
