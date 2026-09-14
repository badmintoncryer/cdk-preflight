package cdk_preflight

import rego.v1

_pf_cbccarn_services := {"codeconnections": true, "codestar-connections": true}

_pf_cbccarn_connection(v) if _pf_cbccarn_services[_pf_codebuildlib_arn_service(v)]

violation contains make_diag_full("pf-codebuild-sourcecredential-codeconnections-arn", "ERROR", name,
	"Properties.Token",
	"AuthType is CODECONNECTIONS but Token is not a connection ARN; ImportSourceCredentials fails with \"Token must be a valid CodeConnections arn\"",
	"Set Token to the arn:aws:codeconnections:...:connection/... of the connection",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-sourcecredential.html") if {
	some name in resources_of_type("AWS::CodeBuild::SourceCredential")
	p := _pf_codebuildlib_props(name)
	_pf_codebuildlib_str(p, "AuthType") == "CODECONNECTIONS"
	tok := _pf_codebuildlib_str(p, "Token")
	not _pf_cbccarn_connection(tok)
}
