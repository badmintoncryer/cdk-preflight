package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-sqlserver-dbname-null", "ERROR", name,
	"Properties.DBName",
	sprintf("DBName is set on engine %v (\"DBName must be null for engine: sqlserver-ex\")", [e]),
	"Drop DBName for SQL Server",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_has(name, "DBName")
	e := _pf_rds_engine(name)
	_pf_rds_engine_in(name, {"sqlserver-"})
}
