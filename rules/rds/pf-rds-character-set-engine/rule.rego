package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-character-set-engine", "ERROR", name,
	"Properties.CharacterSetName",
	sprintf("CharacterSetName is set on engine %v (\"You tried to modify the character set, which isn't supported when creating an instance using version 8.4 of mysql.\")", [e]),
	"Drop CharacterSetName, or use an Oracle engine",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_has(name, "CharacterSetName")
	e := _pf_rds_engine(name)
	_pf_rds_engine_in(name, {"mysql", "mariadb", "postgres", "db2-", "aurora-mysql", "aurora-postgresql"})
}
