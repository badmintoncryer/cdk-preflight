package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-dfcc-compression", "ERROR", name,
	sprintf("%s.CompressionFormat", [path]),
	sprintf("CompressionFormat is '%s' while data format conversion is enabled; the stream create fails with \"The S3 destination's compression format must be set to UNCOMPRESSED when data format conversion is enabled\"", [f]),
	"Drop CompressionFormat (or set UNCOMPRESSED) and compress inside the ParquetSerDe / OrcSerDe instead",
	"https://docs.aws.amazon.com/firehose/latest/dev/record-format-conversion.html") if {
	some [name, path, c] in _pf_fhlib_dests
	dfcc := object.get(c, "DataFormatConversionConfiguration", null)
	is_object(dfcc)
	coerce_to_bool(object.get(dfcc, "Enabled", false)) == true
	f := object.get(c, "CompressionFormat", null)
	_pf_fhlib_lit(f)
	f != "UNCOMPRESSED"
}
