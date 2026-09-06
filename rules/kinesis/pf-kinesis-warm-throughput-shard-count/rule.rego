package cdk_preflight

import rego.v1

_pf_kinwt_url := "https://docs.aws.amazon.com/kinesis/latest/APIReference/API_CreateStream.html"

_pf_kinwt_fix := "Drop WarmThroughputMiBps, or make the stream on-demand and remove ShardCount"

violation contains make_diag_full("pf-kinesis-warm-throughput-shard-count", "ERROR", name,
	"Properties.WarmThroughputMiBps",
	"the stream sets both WarmThroughputMiBps and ShardCount; the stack fails with \"WarmThroughputMiBps can only be set for ON_DEMAND streams\" (CreateStream answers \"Either 'warmThroughputMiBps' or 'shardCount' can be set but not both\")",
	_pf_kinwt_fix, _pf_kinwt_url) if {
	some name in resources_of_type("AWS::Kinesis::Stream")
	_pf_kinlib_has(_pf_kinlib_props(name), "WarmThroughputMiBps")
	_pf_kinlib_has(_pf_kinlib_props(name), "ShardCount")
}

violation contains make_diag_full("pf-kinesis-warm-throughput-shard-count", "ERROR", name,
	"Properties.WarmThroughputMiBps",
	"warm throughput is an on-demand feature but StreamMode is PROVISIONED; CreateStream fails with \"WarmThroughputMiBps cannot be set while creating stream in Provisioned StreamMode\"",
	_pf_kinwt_fix, _pf_kinwt_url) if {
	some name in resources_of_type("AWS::Kinesis::Stream")
	_pf_kinlib_has(_pf_kinlib_props(name), "WarmThroughputMiBps")
	resolve(name, "Properties.StreamModeDetails.StreamMode") == "PROVISIONED"
}
