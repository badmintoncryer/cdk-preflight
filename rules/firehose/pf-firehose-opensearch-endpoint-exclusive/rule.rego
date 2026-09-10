package cdk_preflight

import rego.v1

_pf_pf_firehose_opensearch_endpoint_exclusive_n(c) := n if {
	n := count([k | some k in {"DomainARN", "ClusterEndpoint"}; object.get(c, k, "__pf_absent") != "__pf_absent"])
}

violation contains make_diag_full("pf-firehose-opensearch-endpoint-exclusive", "ERROR", name,
	sprintf("%s.DomainARN", [path]),
	"both DomainARN and ClusterEndpoint are set; the stream create fails with \"Cannot provide both Elasticsearch cluster endpoint and domain ARN. Provide either the cluster endpoint or domain arn.\"",
	"Set exactly one of DomainARN or ClusterEndpoint",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_AmazonopensearchserviceDestinationConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path in {"Properties.AmazonopensearchserviceDestinationConfiguration", "Properties.ElasticsearchDestinationConfiguration"}
	_pf_pf_firehose_opensearch_endpoint_exclusive_n(c) == 2
}
