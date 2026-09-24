package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-framework-controls-min-one", "ERROR", name,
	"Properties.FrameworkControls",
	"FrameworkControls is empty: AWS Backup Audit Manager rejects a framework with no control",
	"Add at least one FrameworkControls entry (for example BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-framework-frameworkcontrol.html") if {
	some name in resources_of_type("AWS::Backup::Framework")
	fc := _pf_bklib_get(_pf_bklib_props(name), "FrameworkControls")
	is_array(fc)
	count(fc) < 1
}
