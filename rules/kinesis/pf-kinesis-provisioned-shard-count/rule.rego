package cdk_preflight

import rego.v1

_pf_kinpsc_url := "https://docs.aws.amazon.com/kinesis/latest/APIReference/API_CreateStream.html"

# Only an explicit PROVISIONED mode is a violation: a stream with neither
# StreamModeDetails nor ShardCount creates fine on the service default.
violation contains make_diag_full("pf-kinesis-provisioned-shard-count", "ERROR", name,
	"Properties.ShardCount",
	"StreamMode is PROVISIONED but ShardCount is missing; the stack fails with \"ShardCount is expected when StreamMode=PROVISIONED\"",
	"Set ShardCount, or switch StreamModeDetails.StreamMode to ON_DEMAND",
	_pf_kinpsc_url) if {
	some name in resources_of_type("AWS::Kinesis::Stream")
	resolve(name, "Properties.StreamModeDetails.StreamMode") == "PROVISIONED"
	not _pf_kinlib_has(_pf_kinlib_props(name), "ShardCount")
}
