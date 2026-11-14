package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-kinesisanalytics-sql-configuration-runtime", "ERROR", name,
	"Properties.ApplicationConfiguration.SqlApplicationConfiguration",
	sprintf("SqlApplicationConfiguration is set on runtime %v; CloudFormation refuses the property (\"Unsupported property [SqlApplicationConfiguration]\"), and CreateApplication would refuse it on a non-SQL runtime anyway", [rt]),
	"Drop SqlApplicationConfiguration — Flink applications configure sources and sinks in their own code",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_ApplicationConfiguration.html") if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	_pf_kinlib_has(_pf_kinlib_appcfg(name), "SqlApplicationConfiguration")
	rt := _pf_kinlib_runtime(name)
	rt != "SQL-1_0"
}
