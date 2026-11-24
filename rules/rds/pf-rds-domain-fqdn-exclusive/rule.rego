package cdk_preflight

import rego.v1

# Domain（AWS Managed AD のディレクトリ ID）と DomainFqdn 系（自己管理 AD）は排他。

violation contains make_diag_full("pf-rds-domain-fqdn-exclusive", "ERROR", name,
	"Properties.DomainFqdn",
	"Domain and DomainFqdn are both set; a DB instance joins either an AWS Managed Microsoft AD (Domain) or a self-managed AD (DomainFqdn, DomainOu, DomainAuthSecretArn, DomainDnsIps), not both",
	"Keep Domain with DomainIAMRoleName for AWS Managed Microsoft AD, or the Domain* self-managed set without Domain",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_has(name, "Domain")
	_pf_rds_has(name, "DomainFqdn")
}
