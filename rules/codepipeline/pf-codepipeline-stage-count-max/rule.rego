package cdk_preflight

import rego.v1

# 50 stages per pipeline (Service Quotas: Total stages per pipeline, Adjustable: false).
violation contains make_diag_full("pf-codepipeline-stage-count-max", "ERROR", name,
	"Properties.Stages",
	sprintf("the pipeline declares %d stages; CreatePipeline fails with \"InvalidStructureException: Pipeline has too many stages. There can only be up to 50 stages in a pipeline\"", [n]),
	"Split the work across pipelines so no pipeline exceeds 50 stages",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-pipeline-structure.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	n := count(_pf_cplib_stages(name))
	n > 50
}
