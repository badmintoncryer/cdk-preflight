package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-processor-features-engine", "ERROR", name,
	"Properties.ProcessorFeatures",
	sprintf("ProcessorFeatures is set on engine %v (\"The given ProcessorFeature coreCount is unavailable for this DB instance class.\")", [e]),
	"Drop ProcessorFeatures for this engine",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_has(name, "ProcessorFeatures")
	e := _pf_rds_engine(name)
	_pf_rds_engine_in(name, {"mysql", "mariadb", "postgres", "db2-", "aurora-mysql", "aurora-postgresql"})
}
