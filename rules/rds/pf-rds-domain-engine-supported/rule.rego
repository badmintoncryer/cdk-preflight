package cdk_preflight

import rego.v1

# CFn DBInstance Domain: 'Currently, only Db2, MySQL, Microsoft SQL Server, Oracle, and PostgreSQL DB instances
# can be created in an Active Directory Domain.' Aurora はクラスタ側の設定なので見ない。リテラルのエンジン名だけを見る。

violation contains make_diag_full("pf-rds-domain-engine-supported", "ERROR", name,
	"Properties.Domain",
	"Domain/DomainFqdn is set on a MariaDB DB instance; only Db2, MySQL, SQL Server, Oracle and PostgreSQL DB instances can join an Active Directory domain",
	"Remove the Domain* properties, or use an engine that supports Kerberos authentication",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	some k in ["Domain", "DomainFqdn"]
	_pf_rds_has(name, k)
	_pf_rds_family(name) == "mariadb"
}
