package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-iceberg-catalog-arn-format", "ERROR", name,
	"Properties.IcebergDestinationConfiguration.CatalogConfiguration.CatalogArn",
	sprintf("CatalogArn '%s' is not a Glue catalog ARN; the stream create fails with \"failed to satisfy constraint: Member must satisfy regular expression pattern: arn:.*:glue:.*:\\d{12}:catalog\"", [arn]),
	"Write the ARN as arn:aws:glue:<region>:<account>:catalog",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_CatalogConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.IcebergDestinationConfiguration"
	arn := object.get(object.get(c, "CatalogConfiguration", {}), "CatalogArn", null)
	_pf_fhlib_lit(arn)
	startswith(arn, "arn:")
	not regex.match(`^arn:[^:]*:glue:[^:]*:[0-9]{12}:catalog(/[a-z0-9_-]+){0,2}$`, arn)
}
