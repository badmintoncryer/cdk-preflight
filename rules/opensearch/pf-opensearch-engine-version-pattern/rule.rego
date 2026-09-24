package cdk_preflight

import rego.v1

# The server-side pattern verbatim from CreateDomain's validation message.

violation contains make_diag_full("pf-opensearch-engine-version-pattern", "ERROR", name,
	"Properties.EngineVersion",
	sprintf("EngineVersion \"%v\" is not of the form Elasticsearch_x.y or OpenSearch_x.y; CreateDomain answers \"failed to satisfy constraint: Member must satisfy regular expression pattern\"", [v]),
	"Write the version as OpenSearch_2.19 or Elasticsearch_7.10 (underscore, one dot)",
	"https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_CreateDomain.html") if {
	some name in _pf_os_domains
	v := resolve(name, "Properties.EngineVersion")
	is_string(v)
	not regex.match(`^Elasticsearch_[0-9]{1}\.[0-9]{1,2}$|^OpenSearch_[0-9]{1,2}\.[0-9]{1,2}$`, v)
}
