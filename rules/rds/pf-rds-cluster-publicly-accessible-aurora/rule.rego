package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-cluster-publicly-accessible-aurora", "ERROR", name,
	"Properties.PubliclyAccessible",
	sprintf("PubliclyAccessible is set on engine %v (\"PubliclyAccessible isn't supported for DB engine aurora-postgresql.\")", [e]),
	"Drop PubliclyAccessible for Aurora",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	_pf_rds_has(name, "PubliclyAccessible")
	e := _pf_rds_engine(name)
	_pf_rds_engine_in(name, {"aurora-mysql", "aurora-postgresql"})
}
