package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-processor-retries-range", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors.%d.Parameters", [path, i]),
	sprintf("NumberOfRetries is %v; the stream create fails with \"Number of retries for lambda must be between 0 and 300.\"", [v]),
	"Set NumberOfRetries between 0 and 300",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_ProcessorParameter.html") if {
	some [name, path, i, t, pr] in _pf_fhlib_procs
	t == "Lambda"
	some raw in _pf_fhlib_params(pr, "NumberOfRetries")
	v := to_number(raw)
	_pf_fhprr_out(v)
}

_pf_fhprr_out(v) if v < 0

_pf_fhprr_out(v) if v > 300
