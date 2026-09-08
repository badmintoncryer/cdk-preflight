package cdk_preflight

import rego.v1

_pf_rdslogs := {
	"postgres": {"postgresql", "upgrade", "iam-db-auth-error"},
	"mysql": {"audit", "error", "general", "slowquery", "iam-db-auth-error"},
	"mariadb": {"audit", "error", "general", "slowquery", "iam-db-auth-error"},
	"oracle-": {"alert", "audit", "listener", "trace", "oemagent"},
	"sqlserver-": {"agent", "error"},
	"db2-": {"diag.log", "notify.log"},
}

violation contains make_diag_full("pf-rds-logs-exports-engine", "ERROR", name,
	"Properties.EnableCloudwatchLogsExports",
	sprintf("Log type %v is not exportable for engine %v (\"You cannot use the log types 'audit' with engine version postgres 18.3. For supported log types, see the documentation.\")", [v, e]),
	"Use the log types the engine supports",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	e := _pf_rds_engine(name)
	allowed := _pf_rdslogs[_pf_rds_family(name)]
	some it in flatten_list(name, "Properties.EnableCloudwatchLogsExports")
	v := it.value
	is_string(v)
	not v in allowed
}
