package cdk_preflight

import rego.v1

_pf_cbcte_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-environment.html"

_pf_cbcte_lambda_env := {"LINUX_LAMBDA_CONTAINER", "ARM_LAMBDA_CONTAINER"}

violation contains make_diag_full("pf-codebuild-compute-type-environment-type", "ERROR", name,
	"Properties.Environment.ComputeType",
	sprintf("ComputeType %s is a Lambda compute type but Environment.Type is %s; CreateProject fails with \"Invalid compute type provided\"", [c, t]),
	"Use a Lambda environment type, or pick a compute type the environment supports", _pf_cbcte_url) if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	c := _pf_codebuildlib_compute_type(name)
	startswith(c, "BUILD_LAMBDA_")
	t := _pf_codebuildlib_env_type(name)
	not _pf_cbcte_lambda_env[t]
}

violation contains make_diag_full("pf-codebuild-compute-type-environment-type", "ERROR", name,
	"Properties.Environment.ComputeType",
	sprintf("Environment.Type %s only runs Lambda compute types but ComputeType is %s; CreateProject fails with \"Compute type %s is not supported for %s\"", [t, c, c, t]),
	"Use one of the BUILD_LAMBDA_* compute types in a Lambda environment", _pf_cbcte_url) if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	c := _pf_codebuildlib_compute_type(name)
	startswith(c, "BUILD_GENERAL1_")
	t := _pf_codebuildlib_env_type(name)
	_pf_cbcte_lambda_env[t]
}
