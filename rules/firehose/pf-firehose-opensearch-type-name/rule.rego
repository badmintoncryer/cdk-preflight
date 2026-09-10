package cdk_preflight

import rego.v1

_pf_fhotn_modern(v) if startswith(v, "OpenSearch_")

_pf_fhotn_modern(v) if regex.match(`^Elasticsearch_[789]`, v)

violation contains make_diag_full("pf-firehose-opensearch-type-name", "ERROR", name,
	sprintf("%s.TypeName", [path]),
	sprintf("TypeName '%s' is set while the destination domain runs %s; the stream create fails with \"Types are deprecated in Elasticsearch version 7+ and all OpenSearch versions. TypeName must be empty.\"", [tn, ver]),
	"Drop TypeName - types no longer exist on Elasticsearch 7+ and OpenSearch domains",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_AmazonopensearchserviceDestinationConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path in {"Properties.AmazonopensearchserviceDestinationConfiguration", "Properties.ElasticsearchDestinationConfiguration"}
	tn := object.get(c, "TypeName", null)
	_pf_fhlib_lit(tn)
	count(tn) > 0
	target := resolve(name, sprintf("%s.DomainARN", [path]))
	target in resources_of_type("AWS::OpenSearchService::Domain")
	ver := resolve(target, "Properties.EngineVersion")
	_pf_fhotn_modern(ver)
}
