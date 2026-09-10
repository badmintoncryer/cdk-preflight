package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-aoss-collection-endpoint", "ERROR", name,
	"Properties.AmazonOpenSearchServerlessDestinationConfiguration.CollectionEndpoint",
	"CollectionEndpoint is not set; the stream create fails with \"Must specify collection endpoint for delivery to OpenSearch serverless.\"",
	"Set CollectionEndpoint to the collection's https endpoint",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_AmazonOpenSearchServerlessDestinationConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.AmazonOpenSearchServerlessDestinationConfiguration"
	object.get(c, "CollectionEndpoint", "__pf_absent") == "__pf_absent"
}
