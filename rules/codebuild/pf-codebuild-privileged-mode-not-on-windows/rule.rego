package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-privileged-mode-not-on-windows", "ERROR", name,
	"Properties.Environment.PrivilegedMode",
	sprintf("PrivilegedMode is true on %s; CreateProject fails with \"PrivilegedMode is not supported for %s projects\". The Docker daemon (and so LOCAL_DOCKER_LAYER_CACHE) is only available in a Linux environment", [t, t]),
	"Drop PrivilegedMode, or run the build in a Linux environment",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-environment.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	e := _pf_codebuildlib_env(name)
	_pf_codebuildlib_true(object.get(e, "PrivilegedMode", null))
	t := _pf_codebuildlib_str(e, "Type")
	startswith(t, "WINDOWS_SERVER_")
}
