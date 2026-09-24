package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-report-setting-framework-arns-required", "ERROR", name,
	"Properties.ReportSetting.FrameworkArns",
	sprintf("ReportTemplate %v needs FrameworkArns: a compliance report is scoped to the frameworks it reports on", [t]),
	"List the ARNs of the Backup Audit Manager frameworks in ReportSetting.FrameworkArns",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-reportplan-reportsetting.html") if {
	some name in resources_of_type("AWS::Backup::ReportPlan")
	rs := _pf_bklib_get(_pf_bklib_props(name), "ReportSetting")
	t := _pf_bklib_str(rs, "ReportTemplate")
	t in {"CONTROL_COMPLIANCE_REPORT", "RESOURCE_COMPLIANCE_REPORT"}
	arns := object.get(rs, "FrameworkArns", [])
	is_array(arns)
	count(arns) < 1
}
