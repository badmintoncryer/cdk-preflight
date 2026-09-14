package cdk_preflight

import rego.v1

# Also a pairing rather than a threshold: two resources naming the same
# ServerType, found by logical id so the pair is reported once.
violation contains make_diag_full("pf-codebuild-sourcecredential-one-per-server-type", "ERROR", b,
	"Properties.ServerType",
	sprintf("%s already imports a %s credential, and CodeBuild keeps one per server type per Region; the stack fails with \"Access token with server type %s already exists. Delete its source credential and try again.\"", [a, st, st]),
	"Keep one SourceCredential per server type, or split them across Regions",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-sourcecredential.html") if {
	some a in resources_of_type("AWS::CodeBuild::SourceCredential")
	some b in resources_of_type("AWS::CodeBuild::SourceCredential")
	a < b
	st := _pf_codebuildlib_str(_pf_codebuildlib_props(a), "ServerType")
	_pf_codebuildlib_str(_pf_codebuildlib_props(b), "ServerType") == st
}
