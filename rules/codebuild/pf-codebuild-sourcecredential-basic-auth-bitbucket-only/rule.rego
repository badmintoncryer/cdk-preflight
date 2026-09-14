package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-sourcecredential-basic-auth-bitbucket-only", "ERROR", name,
	"Properties.AuthType",
	sprintf("AuthType is BASIC_AUTH on a %s credential; ImportSourceCredentials fails with \"Invalid AuthType provided for ServerType %s\"", [st, st]),
	"Use PERSONAL_ACCESS_TOKEN, CODECONNECTIONS or SECRETS_MANAGER for this provider",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-sourcecredential.html") if {
	some name in resources_of_type("AWS::CodeBuild::SourceCredential")
	p := _pf_codebuildlib_props(name)
	_pf_codebuildlib_str(p, "AuthType") == "BASIC_AUTH"
	st := _pf_codebuildlib_str(p, "ServerType")
	st != "BITBUCKET"
}
