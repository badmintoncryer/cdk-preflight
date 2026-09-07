package cdk_preflight

import rego.v1

_pf_leeas_fix := "Point EventSourceArn at an SQS queue, Kinesis stream, DynamoDB stream, Kafka cluster, Amazon MQ broker or DocumentDB cluster"

_pf_leeas_url := "https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html"

_pf_leeas_ok := {"sqs", "kinesis", "dynamodb", "kafka", "mq", "rds"}

violation contains make_diag_full("pf-lambda-esm-event-source-arn-service", "ERROR", name,
	"Properties.EventSourceArn",
	sprintf("EventSourceArn names the '%v' service; Lambda polls only SQS, Kinesis, DynamoDB Streams, Kafka, Amazon MQ and DocumentDB", [parts[2]]),
	_pf_leeas_fix, _pf_leeas_url) if {
	some name in _pf_lam_esm
	parts := _pf_lam_arn(resolve(name, "Properties.EventSourceArn"))
	not parts[2] in _pf_leeas_ok
}
