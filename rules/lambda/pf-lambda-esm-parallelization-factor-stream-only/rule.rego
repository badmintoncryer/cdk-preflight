package cdk_preflight

import rego.v1

_pf_lepfs_fix := "Drop ParallelizationFactor, or point the mapping at a Kinesis or DynamoDB stream"

_pf_lepfs_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-parallelization-factor-stream-only", "ERROR", name,
	"Properties.ParallelizationFactor",
	"ParallelizationFactor on a source that does not support it; the factor multiplies concurrent batches per shard, and only Kinesis and DynamoDB Streams have shards",
	_pf_lepfs_fix, _pf_lepfs_url) if {
	some name in _pf_lam_esm
	_pf_lam_has(name, "ParallelizationFactor")
	some other in ["sqs","mq","docdb","kafka","selfkafka"]
	_pf_lam_is(name, other)
}
