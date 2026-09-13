package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-glue-crawler-configuration-json", "ERROR", name,
	"Properties.Configuration",
	"The crawler Configuration is not well-formed JSON; CreateCrawler fails with \"Crawler configuration not valid: Error parsing JSON\"",
	"Write Configuration as a JSON document, e.g. {\"Version\": 1.0, \"Grouping\": {\"TableGroupingPolicy\": \"CombineCompatibleSchemas\"}}",
	"https://docs.aws.amazon.com/glue/latest/dg/crawler-configuration.html") if {
	some name in resources_of_type("AWS::Glue::Crawler")
	cfg := _pf_gluelib_config(name)
	not json.is_valid(cfg)
}
