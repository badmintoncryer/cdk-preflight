package cdk_preflight

import rego.v1

# SQL-1_0 is still a valid enum value in the CloudFormation schema, but
# CreateApplication refuses it in every region (measured us-east-1 and
# ap-northeast-1, 2026-09-06).
violation contains make_diag_full("pf-kinesisanalytics-sql-runtime-unsupported", "ERROR", name,
	"Properties.RuntimeEnvironment",
	"RuntimeEnvironment is SQL-1_0; CreateApplication fails with \"CreateApplication is not supported for SQL applications in this Region. You can use KDA Studio to build streaming applications with Flink SQL.\"",
	"Use a FLINK runtime, or a ZEPPELIN-FLINK Studio notebook for Flink SQL",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_CreateApplication.html") if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	_pf_kinlib_runtime(name) == "SQL-1_0"
}
