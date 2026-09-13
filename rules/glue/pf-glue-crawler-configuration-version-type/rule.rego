package cdk_preflight

import rego.v1

# "Version": "1.0" as a string is rejected even though the JSON parses; the
# neighbouring rule only sees the key being absent.
violation contains make_diag_full("pf-glue-crawler-configuration-version-type", "ERROR", name,
	"Properties.Configuration.Version",
	"The crawler Configuration has Version as a string; CreateCrawler fails with \"Crawler configuration not valid: Version type invalid: expected Double, received String\"",
	"Write the version as a JSON number, e.g. {\"Version\": 1.0, ...}",
	"https://docs.aws.amazon.com/glue/latest/dg/crawler-configuration.html") if {
	some name in resources_of_type("AWS::Glue::Crawler")
	raw := _pf_gluelib_config(name)
	json.is_valid(raw)
	cfg := json.unmarshal(raw)
	is_object(cfg)
	v := object.get(cfg, "Version", null)
	v != null
	not is_number(v)
}
