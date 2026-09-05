package cdk_preflight

import rego.v1

_pf_wafsr_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-wafv2-webacl.html"

_pf_wafsr_fix := "Deploy CLOUDFRONT-scoped WAFv2 resources from a stack in us-east-1 (env: { region: 'us-east-1' }), or use Scope REGIONAL for regional resources"

_pf_wafsr_types := {"AWS::WAFv2::WebACL", "AWS::WAFv2::RuleGroup", "AWS::WAFv2::IPSet", "AWS::WAFv2::RegexPatternSet"}

# Needs the deploy environment (enforce mode only).
violation contains make_diag_full("pf-wafv2-scope-region", "ERROR", name, "Properties.Scope",
	sprintf("Scope CLOUDFRONT is only accepted in us-east-1, but this stack deploys to %s; the create call fails with \"The scope is not valid.\"", [region]),
	_pf_wafsr_fix, _pf_wafsr_url) if {
	region := data.cdk_preflight.deploy_region
	region != "us-east-1"
	some t in _pf_wafsr_types
	some name in resources_of_type(t)
	resolve(name, "Properties.Scope") == "CLOUDFRONT"
}
