package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-processor-lambda-arn", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors.%d.Parameters", [path, i]),
	"a Lambda processor has no LambdaArn parameter; the stream create fails with \"LambdaArn is required when Lambda processor is used.\"",
	"Add a ProcessorParameter with ParameterName LambdaArn",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_Processor.html") if {
	some [name, path, i, t, pr] in _pf_fhlib_procs
	t == "Lambda"
	not _pf_fhlib_has_param(pr, "LambdaArn")
}
