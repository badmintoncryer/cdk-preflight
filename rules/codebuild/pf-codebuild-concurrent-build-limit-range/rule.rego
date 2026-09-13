package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-concurrent-build-limit-range", "ERROR", name,
	"Properties.ConcurrentBuildLimit",
	sprintf("ConcurrentBuildLimit is %v; CreateProject fails with \"Project level concurrent builds limit should be greater than 0\"", [n]),
	"Set ConcurrentBuildLimit to 1 or more, or leave it out to use the account limit",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-project.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	n := _pf_codebuildlib_num(object.get(_pf_codebuildlib_props(name), "ConcurrentBuildLimit", null))
	n < 1
}
