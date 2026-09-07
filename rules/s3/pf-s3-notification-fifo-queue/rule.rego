package cdk_preflight

import rego.v1

_pf_s3nfq_fix := "Point the notification at a standard SQS queue"

_pf_s3nfq_url := "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketNotificationConfiguration.html"

violation contains make_diag_full("pf-s3-notification-fifo-queue", "ERROR", name,
	sprintf("Properties.NotificationConfiguration.QueueConfigurations.%d.Queue", [c.index]),
	sprintf("'%v' is a FIFO queue; S3 event notifications only support standard queues", [arn]),
	_pf_s3nfq_fix, _pf_s3nfq_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some c in flatten_list(name, "Properties.NotificationConfiguration.QueueConfigurations")
	is_object(c.value)
	arn := _pf_s3lib_lit(object.get(c.value, "Queue", null))
	endswith(arn, ".fifo")
}
