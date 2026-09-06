package cdk_preflight

import rego.v1

# Still in the CloudFormation enum, gone from the service: Flink 1.6 / 1.8 /
# 1.11 stopped being creatable in February 2025 and 1.13 in October 2025, and
# the two older Studio runtimes went with them.
_pf_kinrtd_dead := {"FLINK-1_6", "FLINK-1_8", "FLINK-1_11", "FLINK-1_13", "ZEPPELIN-FLINK-1_0", "ZEPPELIN-FLINK-2_0"}

violation contains make_diag_full("pf-kinesisanalytics-runtime-deprecated", "ERROR", name,
	"Properties.RuntimeEnvironment",
	sprintf("runtime %v is deprecated; CreateApplication fails with \"Runtime %v is deprecated.\"", [rt, rt]),
	"Move to a supported runtime (FLINK-1_20 for applications, ZEPPELIN-FLINK-3_0 for Studio notebooks)",
	"https://docs.aws.amazon.com/managed-flink/latest/java/release-version-list.html") if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	rt := _pf_kinlib_runtime(name)
	rt in _pf_kinrtd_dead
}
