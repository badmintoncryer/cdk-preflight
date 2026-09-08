package cdk_preflight

import rego.v1

_pf_rdsclogs := {
	"aurora-postgresql": {"postgresql", "instance", "iam-db-auth-error"},
	"aurora-mysql": {"audit", "error", "general", "slowquery", "iam-db-auth-error"},
	"postgres": {"postgresql", "upgrade", "iam-db-auth-error"},
	"mysql": {"audit", "error", "general", "slowquery", "iam-db-auth-error"},
}

violation contains make_diag_full("pf-rds-cluster-logs-exports-engine", "ERROR", name,
	"Properties.EnableCloudwatchLogsExports",
	sprintf("Log type %v is not exportable for engine %v (\"You cannot use the log types 'general' with engine version aurora-postgresql 17.7. For supported log types, see the documentation.\")", [v, e]),
	"Use the log types the engine supports",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	e := _pf_rds_engine(name)
	allowed := _pf_rdsclogs[_pf_rds_family(name)]
	some it in flatten_list(name, "Properties.EnableCloudwatchLogsExports")
	v := it.value
	is_string(v)
	not v in allowed
}
