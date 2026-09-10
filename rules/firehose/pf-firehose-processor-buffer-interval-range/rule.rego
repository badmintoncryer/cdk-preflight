package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-processor-buffer-interval-range", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors.%d.Parameters", [path, i]),
	sprintf("BufferIntervalInSeconds is %v; the stream create fails with \"BufferIntervalInSeconds for lambda processor must be between 0 and 900.\"", [v]),
	"Set BufferIntervalInSeconds between 0 and 900",
	"https://docs.aws.amazon.com/firehose/latest/dev/data-transformation.html") if {
	some [name, path, i, t, pr] in _pf_fhlib_procs
	t == "Lambda"
	some raw in _pf_fhlib_params(pr, "BufferIntervalInSeconds")
	v := to_number(raw)
	_pf_pf_firehose_processor_buffer_interval_range_out(v)
}

_pf_pf_firehose_processor_buffer_interval_range_out(v) if v < 0

_pf_pf_firehose_processor_buffer_interval_range_out(v) if v > 900
