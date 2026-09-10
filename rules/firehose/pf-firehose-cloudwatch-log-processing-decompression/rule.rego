package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-cloudwatch-log-processing-decompression", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors.%d", [path, i]),
	"a CloudWatchLogProcessing processor has no Decompression processor beside it; the stream create fails with \"CloudWatchLogProcessingProcessor can only be enabled with DecompressionProcessor\"",
	"Add a Decompression processor to the same processing configuration",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_Processor.html") if {
	some [name, path, i, t, _] in _pf_fhlib_procs
	t == "CloudWatchLogProcessing"
	count([j | some [nm, p, j, tt, _] in _pf_fhlib_procs; nm == name; p == path; tt == "Decompression"]) == 0
}
