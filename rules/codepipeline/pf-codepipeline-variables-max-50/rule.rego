package cdk_preflight

import rego.v1

# 50 pipeline variables. Service Quotas lists no adjustable quota for this limit.
violation contains make_diag_full("pf-codepipeline-variables-max-50", "ERROR", name,
	"Properties.Variables",
	sprintf("the pipeline declares %d variables; CreatePipeline fails with \"failed to satisfy constraint: Member must have length less than or equal to 50\"", [n]),
	"Keep the pipeline to 50 variables or fewer",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/pipeline-types.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	n := count(object.get(_pf_cplib_props(name), "Variables", []))
	n > 50
}
