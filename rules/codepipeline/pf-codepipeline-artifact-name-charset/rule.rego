package cdk_preflight

import rego.v1

# An artifact name is at most 100 characters.
violation contains make_diag_full("pf-codepipeline-artifact-name-charset", "ERROR", name,
	sprintf("Properties.Stages.%v.Actions.%v.%v.%v.Name", [si, ai, kind, ii]),
	sprintf("the artifact name is %d characters; CreatePipeline fails with \"failed to satisfy constraint: Member must have length less than or equal to 100\"", [count(n)]),
	"Shorten the artifact name to 100 characters or fewer",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_Artifact.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	some ai, a in _pf_cplib_actions(st)
	_pf_cplib_plain(a)
	some kind in ["InputArtifacts", "OutputArtifacts"]
	some ii, art in object.get(a, kind, [])
	n := _pf_cplib_get(art, "Name")
	_pf_cplib_lit(n)
	count(n) > 100
}

# ... and is restricted to letters, digits, underscore and hyphen.
violation contains make_diag_full("pf-codepipeline-artifact-name-charset", "ERROR", name,
	sprintf("Properties.Stages.%v.Actions.%v.%v.%v.Name", [si, ai, kind, ii]),
	sprintf("artifact name '%v' has characters outside [a-zA-Z0-9_-]; CreatePipeline fails with \"failed to satisfy constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9_\\-]+\"", [n]),
	"Use only letters, digits, underscore and hyphen in the artifact name",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_Artifact.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some si, st in _pf_cplib_stages(name)
	some ai, a in _pf_cplib_actions(st)
	_pf_cplib_plain(a)
	some kind in ["InputArtifacts", "OutputArtifacts"]
	some ii, art in object.get(a, kind, [])
	n := _pf_cplib_get(art, "Name")
	_pf_cplib_lit(n)
	not regex.match(`^[a-zA-Z0-9_-]+$`, n)
}
