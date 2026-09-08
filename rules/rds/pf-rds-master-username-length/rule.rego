package cdk_preflight

import rego.v1

_pf_rdsmu := {
	"mysql": 16,
	"mariadb": 16,
	"aurora-mysql": 16,
	"db2-": 16,
	"oracle-": 30,
	"postgres": 63,
	"aurora-postgresql": 63,
	"sqlserver-": 128,
}

violation contains make_diag_full("pf-rds-master-username-length", "ERROR", name,
	"Properties.MasterUsername",
	sprintf("MasterUsername is %v characters; engine %v allows at most %v (\"Invalid master user name\")", [count(u), e, mx]),
	"Shorten the master user name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	e := _pf_rds_engine(name)
	mx := _pf_rdsmu[_pf_rds_family(name)]
	u := resolve(name, "Properties.MasterUsername")
	is_string(u)
	not input.resources[u]
	count(u) > mx
}
