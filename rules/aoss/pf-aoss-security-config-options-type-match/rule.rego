package cdk_preflight

import rego.v1

# SamlOptions, IamIdentityCenterOptions and IamFederationOptions are all
# Required: No in the schema, and nothing there ties one to Type. Extra blocks
# are fine (saml + SamlOptions + IamIdentityCenterOptions is ACCEPTED); the
# matching one is what has to be there.

violation contains make_diag_full("pf-aoss-security-config-options-type-match", "ERROR", name,
	sprintf("Properties.%v", [blk]),
	sprintf("Type is %v but the config has no %v; CreateSecurityConfig answers \"Saml Config type options should be present for SAML type\" (iamidentitycenter: \"IAM Identity Center options should be present for iamidentitycenter type\", iamfederation: \"Either User or Group attribute must be present for iam federation security config\")", [t, blk]),
	sprintf("Add %v, or set Type to the provider the config actually describes", [blk]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchserverless-securityconfig.html") if {
	some name in resources_of_type("AWS::OpenSearchServerless::SecurityConfig")
	t := resolve(name, "Properties.Type")
	is_string(t)
	blk := _pf_aoss_sc_options[t]
	object.get(_pf_aoss_props(name), blk, "__pf_absent") == "__pf_absent"
}
