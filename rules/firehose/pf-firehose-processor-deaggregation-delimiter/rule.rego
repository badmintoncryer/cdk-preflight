package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-processor-deaggregation-delimiter", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors.%d.Parameters", [path, i]),
	"SubRecordType is DELIMITED but no Delimiter parameter is set; the stream create fails with \"Delimiter should be present for DELIMITED\"",
	"Add a base64-encoded Delimiter parameter",
	"https://docs.aws.amazon.com/firehose/latest/dev/dynamic-partitioning-multirecord-deaggergation.html") if {
	some [name, path, i, t, pr] in _pf_fhlib_procs
	t == "RecordDeAggregation"
	some v in _pf_fhlib_params(pr, "SubRecordType")
	v == "DELIMITED"
	not _pf_fhlib_has_param(pr, "Delimiter")
}
