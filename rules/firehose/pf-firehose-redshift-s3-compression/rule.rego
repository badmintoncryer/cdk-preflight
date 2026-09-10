package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-redshift-s3-compression", "ERROR", name,
	"Properties.RedshiftDestinationConfiguration.S3Configuration.CompressionFormat",
	sprintf("CompressionFormat is '%s', which the Redshift COPY command cannot read; the stream create fails with \"Only the following compression formats are allowed when using Redshift: [UNCOMPRESSED, GZIP]\"", [f]),
	"Use UNCOMPRESSED or GZIP for the intermediate bucket",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_RedshiftDestinationConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.RedshiftDestinationConfiguration"
	f := object.get(object.get(c, "S3Configuration", {}), "CompressionFormat", null)
	_pf_fhlib_lit(f)
	not f in {"UNCOMPRESSED", "GZIP"}
}
