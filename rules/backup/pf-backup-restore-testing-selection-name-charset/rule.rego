package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-restore-testing-selection-name-charset", "ERROR", name,
	"Properties.RestoreTestingSelectionName",
	sprintf("RestoreTestingSelectionName %v contains characters other than letters, digits and underscores (hyphens are rejected)", [n]),
	"Rename the selection without hyphens, e.g. my_selection (CDK default names contain hyphens, so pass an explicit name)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-backup-restoretestingselection.html") if {
	some name in resources_of_type("AWS::Backup::RestoreTestingSelection")
	n := _pf_bklib_str(_pf_bklib_props(name), "RestoreTestingSelectionName")
	not _pf_bklib_underscore_name(n)
}
