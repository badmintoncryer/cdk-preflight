package cdk_preflight

import rego.v1

_pf_gluecmq_queued(name) if {
	some item in flatten_list(name, "Properties.Targets.S3Targets")
	is_object(item.value)
	object.get(item.value, "EventQueueArn", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-glue-crawler-event-mode-requires-event-queue", "ERROR", name,
	"Properties.Targets.S3Targets",
	"RecrawlBehavior is CRAWL_EVENT_MODE but no S3 target carries EventQueueArn; CreateCrawler fails with \"Event queue ARN is required when event crawler is selected.\"",
	"Set EventQueueArn on the S3 target to the SQS queue receiving the Amazon S3 event notifications",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateCrawler.html") if {
	some name in resources_of_type("AWS::Glue::Crawler")
	_pf_gluelib_recrawl(name) == "CRAWL_EVENT_MODE"
	not _pf_gluecmq_queued(name)
}
