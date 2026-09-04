package cdk_preflight

import rego.v1

_pf_sqsname_ok(n) if regex.match(`^[a-zA-Z0-9_-]{1,80}$`, n)

_pf_sqsname_ok(n) if regex.match(`^[a-zA-Z0-9_-]{1,75}\.fifo$`, n)

violation contains make_diag_full("pf-sqs-queue-name-format", "ERROR", name,
	"Properties.QueueName",
	sprintf("QueueName '%s' is rejected: SQS accepts 1-80 characters of letters, numbers, hyphen and underscore (a FIFO queue adds the .fifo suffix)", [n]),
	"Rename the queue using [a-zA-Z0-9_-] within 80 characters (append .fifo only for FIFO queues)",
	"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html") if {
	some name in resources_of_type("AWS::SQS::Queue")
	n := resolve(name, "Properties.QueueName")
	is_string(n)
	not _pf_sqsname_ok(n)
}
