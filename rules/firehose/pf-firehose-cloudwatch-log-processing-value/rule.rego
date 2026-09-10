package cdk_preflight

import rego.v1

_pf_fhcwv_ok(pr) if {
	some v in _pf_fhlib_params(pr, "DataMessageExtraction")
	lower(v) in {"true", "false"}
}

_pf_fhcwv_ok(pr) if {
	some v in _pf_fhlib_params(pr, "DataMessageExtraction")
	not is_string(v)
}

violation contains make_diag_full("pf-firehose-cloudwatch-log-processing-value", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors.%d.Parameters", [path, i]),
	"a CloudWatchLogProcessing processor needs DataMessageExtraction set to True or False; the stream create fails with \"Invalid parameter value for DataMessageExtraction. Allowed values are True and False.\"",
	"Add a DataMessageExtraction parameter whose value is True or False",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_ProcessorParameter.html") if {
	some [name, path, i, t, pr] in _pf_fhlib_procs
	t == "CloudWatchLogProcessing"
	not _pf_fhcwv_ok(pr)
}
