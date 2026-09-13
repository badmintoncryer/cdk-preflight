package cdk_preflight

import rego.v1

# A pipeline made only of source actions has nothing to run.
violation contains make_diag_full("pf-codepipeline-non-source-stage-required", "ERROR", name,
	"Properties.Stages",
	"every action in the pipeline has category Source; CreatePipeline fails with \"InvalidStructureException: Pipeline should contain at least 1 action whose category is not Source\"",
	"Add a Build, Test, Deploy, Approval, Invoke or Compute action to a later stage",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-pipeline-structure.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	stages := _pf_cplib_stages(name)
	cats := {c | some st in stages; some a in _pf_cplib_actions(st); c := _pf_cplib_category(a)}
	count(cats) > 0
	every c in cats {c == "Source"}
}
