package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-lambda-compute-no-privileged-mode", "ERROR", name,
	"Properties.Environment.PrivilegedMode",
	sprintf("PrivilegedMode is true on %s; the Lambda compute mode has no Docker daemon and CreateProject fails with \"Cannot specify privilegedMode for lambda compute\"", [t]),
	"Drop PrivilegedMode, or run the build on a container compute type",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-environment.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	e := _pf_codebuildlib_env(name)
	_pf_codebuildlib_true(object.get(e, "PrivilegedMode", null))
	t := _pf_codebuildlib_str(e, "Type")
	endswith(t, "_LAMBDA_CONTAINER")
}
