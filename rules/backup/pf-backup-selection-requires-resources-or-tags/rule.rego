package cdk_preflight

import rego.v1

_pf_bksel_targets(bs) if _pf_bksel_nonempty(bs, "Resources")

_pf_bksel_targets(bs) if _pf_bksel_nonempty(bs, "ListOfTags")

# マーカー（Ref / GetAtt）は「中身が分からない」だけで指定はされているので present 扱い。
_pf_bksel_nonempty(bs, k) if {
	v := _pf_bklib_get(bs, k)
	v != null
	not _pf_bksel_empty_list(v)
}

_pf_bksel_empty_list(v) if {
	is_array(v)
	count(v) == 0
}

violation contains make_diag_full("pf-backup-selection-requires-resources-or-tags", "ERROR", name,
	"Properties.BackupSelection",
	"A backup selection needs a non-empty Resources or ListOfTags section; Conditions alone is rejected with \"Either 'ListOfTags' or 'Resources' section must be non-empty\"",
	"Add Resources (ARNs or a wildcard) or ListOfTags to the selection",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-backup-backupselection-backupselectionresourcetype.html") if {
	some name in resources_of_type("AWS::Backup::BackupSelection")
	bs := _pf_bklib_selection(name)
	not _pf_bksel_targets(bs)
}
