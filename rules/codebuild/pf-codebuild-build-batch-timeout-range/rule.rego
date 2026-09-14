package cdk_preflight

import rego.v1

_pf_cbbtr_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-projectbuildbatchconfig.html"

_pf_cbbtr_mins(name) := n if n := _pf_codebuildlib_num(object.get(_pf_codebuildlib_batch(name), "TimeoutInMins", null))

violation contains make_diag_full("pf-codebuild-build-batch-timeout-range", "ERROR", name,
	"Properties.BuildBatchConfig.TimeoutInMins",
	sprintf("TimeoutInMins is %v; CreateProject fails with \"TimeoutInMins must be between 5 and 2160\"", [n]),
	"Use a batch timeout between 5 and 2160 minutes", _pf_cbbtr_url) if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	n := _pf_cbbtr_mins(name)
	n < 5
}

violation contains make_diag_full("pf-codebuild-build-batch-timeout-range", "ERROR", name,
	"Properties.BuildBatchConfig.TimeoutInMins",
	sprintf("TimeoutInMins is %v; CreateProject fails with \"TimeoutInMins must be between 5 and 2160\"", [n]),
	"Use a batch timeout between 5 and 2160 minutes", _pf_cbbtr_url) if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	n := _pf_cbbtr_mins(name)
	n > 2160
}
