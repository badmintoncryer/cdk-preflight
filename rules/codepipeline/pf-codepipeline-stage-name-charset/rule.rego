package cdk_preflight

import rego.v1

# A stage name is at most 100 characters ...
violation contains make_diag_full("pf-codepipeline-stage-name-charset", "ERROR", name,
	sprintf("Properties.Stages.%v.Name", [si]),
	sprintf("the stage name is %d characters; CreatePipeline fails with \"failed to satisfy constraint: Member must have length less than or equal to 100\"", [count(sn)]),
	"Shorten the stage name to 100 characters or fewer",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_CreatePipeline.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	sn := _pf_cplib_get(st, "Name")
	_pf_cplib_lit(sn)
	count(sn) > 100
}

# ... and is restricted to letters, digits, dot, at-sign, hyphen and underscore.
violation contains make_diag_full("pf-codepipeline-stage-name-charset", "ERROR", name,
	sprintf("Properties.Stages.%v.Name", [si]),
	sprintf("stage name '%v' has characters outside [A-Za-z0-9.@_-]; CreatePipeline fails with \"failed to satisfy constraint: Member must satisfy regular expression pattern: [A-Za-z0-9.@\\-_]+\"", [sn]),
	"Use only letters, digits, dot, at-sign, hyphen and underscore in the stage name",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_CreatePipeline.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	sn := _pf_cplib_get(st, "Name")
	_pf_cplib_lit(sn)
	not regex.match(`^[A-Za-z0-9.@_-]+$`, sn)
}
