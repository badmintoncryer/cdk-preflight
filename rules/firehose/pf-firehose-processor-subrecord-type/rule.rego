package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-processor-subrecord-type", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors.%d.Parameters", [path, i]),
	sprintf("SubRecordType is '%s'; the stream create fails with \"SubRecordType has to be one of JSON, DELIMITED\"", [v]),
	"Use JSON or DELIMITED",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_Processor.html") if {
	some [name, path, i, t, pr] in _pf_fhlib_procs
	t == "RecordDeAggregation"
	some v in _pf_fhlib_params(pr, "SubRecordType")
	_pf_fhlib_lit(v)
	not v in {"JSON", "DELIMITED"}
}
