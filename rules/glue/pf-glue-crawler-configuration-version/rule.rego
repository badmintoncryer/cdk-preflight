package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-glue-crawler-configuration-version", "ERROR", name,
	"Properties.Configuration",
	"The crawler Configuration JSON has no Version field; CreateCrawler fails with \"Crawler configuration not valid: Crawler configuration missing required key: Version.\"",
	"Add \"Version\": 1.0 (a number, not a string) to the Configuration JSON",
	"https://docs.aws.amazon.com/glue/latest/dg/crawler-configuration.html") if {
	some name in resources_of_type("AWS::Glue::Crawler")
	cfg := _pf_gluelib_config(name)
	json.is_valid(cfg)
	parsed := json.unmarshal(cfg)
	is_object(parsed)
	object.get(parsed, "Version", "__pf_absent") == "__pf_absent"
}
