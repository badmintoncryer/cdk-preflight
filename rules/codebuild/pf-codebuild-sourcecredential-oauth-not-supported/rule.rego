package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-sourcecredential-oauth-not-supported", "ERROR", name,
	"Properties.AuthType",
	"AuthType is OAUTH; ImportSourceCredentials fails with \"OAUTH is not supported by the CodeBuild API. To connect to your account with OAUTH, use the AWS CodeBuild console.\"",
	"Connect the provider with OAUTH in the CodeBuild console, or import a PERSONAL_ACCESS_TOKEN credential instead",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-sourcecredential.html") if {
	some name in resources_of_type("AWS::CodeBuild::SourceCredential")
	_pf_codebuildlib_str(_pf_codebuildlib_props(name), "AuthType") == "OAUTH"
}
