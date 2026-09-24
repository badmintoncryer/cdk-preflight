package cdk_preflight

import rego.v1

# WARN にしてある: この allowlist は 2026-09-24 に CreateRestoreTestingSelection が
# 返した列挙そのものだが、AWS が復元テストの対応リソースを増やすと誤検出に変わる。
# 同じ issue の pf-cloudtrail-trail-aes-field-unknown と同じ理由・同じ裁定。
_pf_bkrts_types := {"AURORA", "DOCUMENTDB", "DYNAMODB", "EBS", "EC2", "EFS", "FSX", "NEPTUNE", "RDS", "S3"}

violation contains make_diag_full("pf-backup-restore-testing-selection-protected-resource-type", "WARN", name,
	"Properties.ProtectedResourceType",
	sprintf("ProtectedResourceType %v is not one of the types AWS Backup restore testing supports", [t]),
	"Use one of AURORA, DOCUMENTDB, DYNAMODB, EBS, EC2, EFS, FSX, NEPTUNE, RDS, S3",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-backup-restoretestingselection.html") if {
	some name in resources_of_type("AWS::Backup::RestoreTestingSelection")
	t := _pf_bklib_str(_pf_bklib_props(name), "ProtectedResourceType")
	not t in _pf_bkrts_types
}
