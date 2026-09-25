package cdk_preflight

import rego.v1

# Name is Required: No in the CFN schema and Required: Yes in
# CreateSecurityConfig. The handler does not generate one.

violation contains make_diag_full("pf-aoss-security-config-name-required", "ERROR", name,
	"Properties.Name",
	"the security config has no Name; the CloudFormation handler answers \"Name cannot be empty\" (CreateSecurityConfig itself answers \"1 validation error detected: Value null at 'name' failed to satisfy constraint: Member must not be null\")",
	"Add Name (3-32 characters, lower case letters, digits and hyphens)",
	"https://docs.aws.amazon.com/opensearch-service/latest/ServerlessAPIReference/API_CreateSecurityConfig.html") if {
	some name in resources_of_type("AWS::OpenSearchServerless::SecurityConfig")
	object.get(_pf_aoss_props(name), "Name", "__pf_absent") == "__pf_absent"
}
