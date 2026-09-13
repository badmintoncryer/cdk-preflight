package cdk_preflight

import rego.v1

_pf_gluecrs_s3only := {"CRAWL_EVENT_MODE", "CRAWL_NEW_FOLDERS_ONLY"}

violation contains make_diag_full("pf-glue-crawler-recrawl-behavior-s3-only", "ERROR", name,
	sprintf("Properties.Targets.%s", [k]),
	sprintf("RecrawlBehavior %s is set while the crawler also has %s; CreateCrawler fails with \"RecrawlBehavior \\\"Crawl new folders only\\\" can only apply to Amazon S3 target.\" / \"Only S3 targets are allowed for event based crawlers.\"", [rb, k]),
	"Use RecrawlBehavior CRAWL_EVERYTHING with non-S3 targets, or crawl only Amazon S3 locations",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateCrawler.html") if {
	some name in resources_of_type("AWS::Glue::Crawler")
	rb := _pf_gluelib_recrawl(name)
	rb in _pf_gluecrs_s3only
	some k, v in _pf_gluelib_targets(name)
	k != "S3Targets"
	is_array(v)
	count(v) > 0
}
