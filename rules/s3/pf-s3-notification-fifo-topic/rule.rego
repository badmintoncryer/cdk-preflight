package cdk_preflight

import rego.v1

_pf_s3nft_fix := "Point the notification at a standard SNS topic"

_pf_s3nft_url := "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketNotificationConfiguration.html"

violation contains make_diag_full("pf-s3-notification-fifo-topic", "ERROR", name,
	sprintf("Properties.NotificationConfiguration.TopicConfigurations.%d.Topic", [c.index]),
	sprintf("'%v' is a FIFO topic; S3 event notifications only support standard topics", [arn]),
	_pf_s3nft_fix, _pf_s3nft_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some c in flatten_list(name, "Properties.NotificationConfiguration.TopicConfigurations")
	is_object(c.value)
	arn := _pf_s3lib_lit(object.get(c.value, "Topic", null))
	endswith(arn, ".fifo")
}
