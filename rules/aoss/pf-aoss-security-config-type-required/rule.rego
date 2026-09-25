package cdk_preflight

import rego.v1

# Type is Required: No in the CFN schema and Required: Yes in
# CreateSecurityConfig. The handler does not infer it from the options block.

violation contains make_diag_full("pf-aoss-security-config-type-required", "ERROR", name,
	"Properties.Type",
	"the security config has no Type; the CloudFormation handler answers \"Type cannot be empty\" (CreateSecurityConfig itself answers \"1 validation error detected: Value null at 'type' failed to satisfy constraint: Member must not be null\")",
	"Add Type: saml, iamidentitycenter or iamfederation",
	"https://docs.aws.amazon.com/opensearch-service/latest/ServerlessAPIReference/API_CreateSecurityConfig.html") if {
	some name in resources_of_type("AWS::OpenSearchServerless::SecurityConfig")
	object.get(_pf_aoss_props(name), "Type", "__pf_absent") == "__pf_absent"
}
