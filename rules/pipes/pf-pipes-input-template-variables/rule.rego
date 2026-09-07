package cdk_preflight

import rego.v1

# "Invalid json path reference or predefined variable for placeholder" — an
# InputTemplate may use $.-paths freely but only these eight reserved
# variables. Measured 2026-09-07, pipes:CreatePipe, us-east-1: all eight are
# accepted, aws.pipes.bogus and aws.events.rule-name are refused. Only
# placeholders in the aws.* namespace are checked, so JSON paths and literal
# markup are untouched.
_pf_pipeitv_known := {
	"aws.pipes.pipe-arn", "aws.pipes.pipe-name", "aws.pipes.source-arn",
	"aws.pipes.enrichment-arn", "aws.pipes.target-arn",
	"aws.pipes.event.ingestion-time", "aws.pipes.event", "aws.pipes.event.json",
}

violation contains make_diag_full("pf-pipes-input-template-variables", "ERROR", name,
	sprintf("Properties.%s.InputTemplate", [block]),
	sprintf("<%s> is not a pipe reserved variable; CreatePipe fails with \"Invalid json path reference or predefined variable for placeholder\"", [v]),
	"Use one of the aws.pipes.* reserved variables, or a $. JSON path",
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/pipes-input-transformation.html") if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	some block in ["TargetParameters", "EnrichmentParameters"]
	tmpl := resolve(name, sprintf("Properties.%s.InputTemplate", [block]))
	is_string(tmpl)
	some m in regex.find_all_string_submatch_n(`<([^<>]+)>`, tmpl, -1)
	v := m[1]
	startswith(v, "aws.")
	not v in _pf_pipeitv_known
}
