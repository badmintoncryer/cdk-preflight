package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-selection-list-of-tags-string-equals-only", "ERROR", name,
	sprintf("Properties.BackupSelection.ListOfTags.%d.ConditionType", [t.index]),
	sprintf("ListOfTags only supports ConditionType STRINGEQUALS, got %v: the other operators belong in Conditions", [ct]),
	"Use STRINGEQUALS in ListOfTags, or move the pattern match to Conditions.StringLike",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupselection-backupselectionresourcetype.html") if {
	some name in resources_of_type("AWS::Backup::BackupSelection")
	some t in flatten_list(name, "Properties.BackupSelection.ListOfTags")
	ct := _pf_bklib_str(t.value, "ConditionType")
	ct != "STRINGEQUALS"
}
