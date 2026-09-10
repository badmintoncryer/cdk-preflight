package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-processor-buffer-size-range", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors.%d.Parameters", [path, i]),
	sprintf("BufferSizeInMBs is %v; the stream create fails with \"BufferSizeInMBs for lambda processor must be between 0.2 and 3.\"", [v]),
	"Set BufferSizeInMBs between 0.2 and 3",
	"https://docs.aws.amazon.com/firehose/latest/dev/data-transformation.html") if {
	some [name, path, i, t, pr] in _pf_fhlib_procs
	t == "Lambda"
	some raw in _pf_fhlib_params(pr, "BufferSizeInMBs")
	v := to_number(raw)
	_pf_pf_firehose_processor_buffer_size_range_out(v)
}

_pf_pf_firehose_processor_buffer_size_range_out(v) if v < 0.2

_pf_pf_firehose_processor_buffer_size_range_out(v) if v > 3
