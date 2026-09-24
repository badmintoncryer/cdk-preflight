package cdk_preflight

import rego.v1

# Custom resources ship under two spellings - the "Custom::<name>" family and
# AWS::CloudFormation::CustomResource - and resources_of_type() matches exactly,
# so the prefixed family has to be collected by hand. Rules that use this must
# declare resourceTypes ["*"]: the enforce plugin prunes on exact type names too.
_pf_cfn_custom_resources contains name if {
	some name, r in input.resources
	startswith(object.get(r, "resourceType", ""), "Custom::")
}

_pf_cfn_custom_resources contains name if {
	some name in resources_of_type("AWS::CloudFormation::CustomResource")
}
