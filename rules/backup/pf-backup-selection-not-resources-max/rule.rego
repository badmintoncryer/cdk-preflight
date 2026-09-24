package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-selection-not-resources-max", "ERROR", name,
	"Properties.BackupSelection.NotResources",
	sprintf("NotResources accepts at most 30 ARNs containing a wildcard, got %v (the 500 limit applies only to wildcard-free ARNs)", [count(wild)]),
	"Keep wildcard NotResources entries to 30 or fewer, or exclude by tag instead",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupselection-backupselectionresourcetype.html") if {
	some name in resources_of_type("AWS::Backup::BackupSelection")
	wild := [v |
		some it in flatten_list(name, "Properties.BackupSelection.NotResources")
		v := it.value
		is_string(v)
		contains(v, "*")
	]
	count(wild) > 30
}
