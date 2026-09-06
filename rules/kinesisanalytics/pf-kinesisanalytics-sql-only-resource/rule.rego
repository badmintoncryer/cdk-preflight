package cdk_preflight

import rego.v1

_pf_kinsor_types := ["AWS::KinesisAnalyticsV2::ApplicationOutput", "AWS::KinesisAnalyticsV2::ApplicationReferenceDataSource"]

# These two resources only exist for the SQL runtime, which the service no
# longer creates — so in practice they always fail. Firing on the runtime of
# the application they point at keeps the message actionable.
violation contains make_diag_full("pf-kinesisanalytics-sql-only-resource", "ERROR", name,
	"Properties.ApplicationName",
	sprintf("application %v runs %v, and SQL-only configuration cannot be attached to it; the stack fails with \"You cannot add sql configuration to a Flink application.\"", [target, rt]),
	"Model sources and sinks in the Flink application code instead",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_AddApplicationOutput.html") if {
	some t in _pf_kinsor_types
	some name in resources_of_type(t)
	target := resolve(name, "Properties.ApplicationName")
	is_string(target)
	rt := _pf_kinlib_runtime(target)
	rt != "SQL-1_0"
}
