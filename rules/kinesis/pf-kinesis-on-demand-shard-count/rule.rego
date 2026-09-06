package cdk_preflight

import rego.v1

_pf_kinods_url := "https://docs.aws.amazon.com/kinesis/latest/APIReference/API_CreateStream.html"

violation contains make_diag_full("pf-kinesis-on-demand-shard-count", "ERROR", name,
	"Properties.ShardCount",
	"the stream is ON_DEMAND but also sets ShardCount; the stack fails with \"ShardCount is not expected when StreamMode=ON_DEMAND\"",
	"Drop ShardCount, or set StreamModeDetails.StreamMode to PROVISIONED",
	_pf_kinods_url) if {
	some name in resources_of_type("AWS::Kinesis::Stream")
	resolve(name, "Properties.StreamModeDetails.StreamMode") == "ON_DEMAND"
	_pf_kinlib_has(_pf_kinlib_props(name), "ShardCount")
}
