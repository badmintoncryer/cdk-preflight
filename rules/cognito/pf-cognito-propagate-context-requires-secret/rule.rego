package cdk_preflight

import rego.v1

_pf_cgpcrs_secret(name) if resolve(name, "Properties.GenerateSecret") == true

violation contains make_diag_full("pf-cognito-propagate-context-requires-secret", "ERROR", name,
	"Properties.EnablePropagateAdditionalUserContextData",
	"EnablePropagateAdditionalUserContextData is true on a client with no secret; the client create fails with \"Client Secret is required to set EnablePropagateAdditionalUserContextData as true\"",
	"Set GenerateSecret: true, or drop EnablePropagateAdditionalUserContextData",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	resolve(name, "Properties.EnablePropagateAdditionalUserContextData") == true
	not _pf_cgpcrs_secret(name)
}
