package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-selection-conditions-key-prefix", "ERROR", name,
	sprintf("Properties.BackupSelection.Conditions.%s.%d.ConditionKey", [op, c.index]),
	sprintf("Conditions keys are IAM condition keys and must start with \"aws:ResourceTag/\", got %v", [k]),
	"Write the key as aws:ResourceTag/<tag key> (plain tag keys only work in ListOfTags)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupselection-conditions.html") if {
	some name in resources_of_type("AWS::Backup::BackupSelection")
	some op in ["StringEquals", "StringNotEquals", "StringLike", "StringNotLike"]
	some c in flatten_list(name, sprintf("Properties.BackupSelection.Conditions.%s", [op]))
	k := _pf_bklib_str(c.value, "ConditionKey")
	not startswith(k, "aws:ResourceTag/")
}
