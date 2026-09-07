package cdk_preflight

import rego.v1

_pf_letws_fix := "Drop TumblingWindowInSeconds, or point the mapping at a Kinesis or DynamoDB stream"

_pf_letws_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-tumbling-window-stream-only", "ERROR", name,
	"Properties.TumblingWindowInSeconds",
	"TumblingWindowInSeconds on a source that does not support it; tumbling windows aggregate per shard, which only Kinesis and DynamoDB Streams provide",
	_pf_letws_fix, _pf_letws_url) if {
	some name in _pf_lam_esm
	_pf_lam_has(name, "TumblingWindowInSeconds")
	some other in ["sqs","mq","docdb","kafka","selfkafka"]
	_pf_lam_is(name, other)
}
