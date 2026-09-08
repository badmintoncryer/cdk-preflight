package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-timezone-engine", "ERROR", name,
	"Properties.Timezone",
	sprintf("Timezone is set on engine %v (\"You can't specify a time zone when you create a DB instance running postgres.\")", [e]),
	"Drop Timezone, or use a Db2 / SQL Server engine",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_has(name, "Timezone")
	e := _pf_rds_engine(name)
	_pf_rds_engine_in(name, {"mysql", "mariadb", "postgres", "oracle-", "aurora-mysql", "aurora-postgresql"})
}
