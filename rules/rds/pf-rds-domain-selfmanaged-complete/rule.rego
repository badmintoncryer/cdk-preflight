package cdk_preflight

import rego.v1

# 自己管理 AD への参加は DomainFqdn / DomainOu / DomainAuthSecretArn / DomainDnsIps の 4 点セット。

violation contains make_diag_full("pf-rds-domain-selfmanaged-complete", "ERROR", name,
	"Properties.DomainFqdn",
	"DomainFqdn is set but DomainOu, DomainAuthSecretArn or DomainDnsIps is missing; joining a self-managed Active Directory needs all four",
	"Set DomainOu, DomainAuthSecretArn and DomainDnsIps together with DomainFqdn",
	"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_SQLServer_SelfManagedActiveDirectory.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_has(name, "DomainFqdn")
	some k in ["DomainOu", "DomainAuthSecretArn", "DomainDnsIps"]
	not _pf_rds_has(name, k)
}
