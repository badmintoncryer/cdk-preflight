package cdk_preflight

import rego.v1

_pf_fhrspx_bad contains [name, key] if {
	some [name, path, c] in _pf_fhlib_prefixed
	startswith(path, "Properties.RedshiftDestinationConfiguration")
	some key in {"Prefix", "ErrorOutputPrefix"}
	v := object.get(c, key, null)
	_pf_fhlib_lit(v)
	count(_pf_fhlib_exprs(v)) > 0
}

violation contains make_diag_full("pf-firehose-redshift-prefix-no-expression", "ERROR", name,
	sprintf("Properties.RedshiftDestinationConfiguration.S3Configuration.%s", [key]),
	sprintf("%s uses prefix expressions, which a Redshift destination does not support; the stream create fails with \"Prefix Expressions or ErrorOutputPrefix is currently not supported for this destination\"", [key]),
	"Use a literal prefix for the intermediate S3 location",
	"https://docs.aws.amazon.com/firehose/latest/dev/s3-prefixes.html") if {
	some [name, key] in _pf_fhrspx_bad
}
