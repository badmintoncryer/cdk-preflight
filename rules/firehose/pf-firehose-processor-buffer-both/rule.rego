package cdk_preflight

import rego.v1

_pf_fhpbb_bad contains [name, path, i, "BufferIntervalInSeconds"] if {
	some [name, path, i, t, pr] in _pf_fhlib_procs
	t == "Lambda"
	_pf_fhlib_has_param(pr, "BufferSizeInMBs")
	not _pf_fhlib_has_param(pr, "BufferIntervalInSeconds")
}

_pf_fhpbb_bad contains [name, path, i, "BufferSizeInMBs"] if {
	some [name, path, i, t, pr] in _pf_fhlib_procs
	t == "Lambda"
	_pf_fhlib_has_param(pr, "BufferIntervalInSeconds")
	not _pf_fhlib_has_param(pr, "BufferSizeInMBs")
}

violation contains make_diag_full("pf-firehose-processor-buffer-both", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors.%d.Parameters", [path, i]),
	sprintf("one Lambda buffering hint is set without %s; the stream create fails with \"Both BufferSizeInMBs and BufferIntervalInSeconds are required to configure buffering for lambda processor.\"", [k]),
	"Set BufferSizeInMBs and BufferIntervalInSeconds together, or neither",
	"https://docs.aws.amazon.com/firehose/latest/dev/data-transformation.html") if {
	some [name, path, i, k] in _pf_fhpbb_bad
}
