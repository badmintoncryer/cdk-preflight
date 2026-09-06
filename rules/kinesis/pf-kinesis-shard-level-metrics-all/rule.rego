package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-kinesis-shard-level-metrics-all", "ERROR", name,
	"Properties.DesiredShardLevelMetrics",
	sprintf("DesiredShardLevelMetrics lists ALL together with %v other metric(s); the stack fails with \"DesiredShardLevelMetrics cannot have ALL with other metric names\"", [count(ms) - 1]),
	"List ALL on its own, or drop ALL and name the metrics you want",
	"https://docs.aws.amazon.com/kinesis/latest/APIReference/API_EnableEnhancedMonitoring.html") if {
	some name in resources_of_type("AWS::Kinesis::Stream")
	ms := object.get(_pf_kinlib_props(name), "DesiredShardLevelMetrics", null)
	is_array(ms)
	"ALL" in ms
	count(ms) > 1
}
