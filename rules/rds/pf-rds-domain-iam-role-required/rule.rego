package cdk_preflight

import rego.v1

# AWS Managed AD に参加させるには、Directory Service を呼ぶための IAM ロール名（DomainIAMRoleName）が要る。

violation contains make_diag_full("pf-rds-domain-iam-role-required", "ERROR", name,
	"Properties.Domain",
	"Domain is set without DomainIAMRoleName; RDS needs an IAM role to call AWS Directory Service for the domain join",
	"Set DomainIAMRoleName to a role trusted by rds.amazonaws.com with AmazonRDSDirectoryServiceAccess",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_has(name, "Domain")
	not _pf_rds_has(name, "DomainIAMRoleName")
}
