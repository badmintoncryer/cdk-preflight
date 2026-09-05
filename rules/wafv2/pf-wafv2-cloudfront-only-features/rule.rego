package cdk_preflight

import rego.v1

_pf_wafcf_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_AWSManagedRulesATPRuleSet.html"

_pf_wafcf_fix := "Drop ResponseInspection / Monetize from REGIONAL web ACLs, and add MonetizationConfig to a CLOUDFRONT web ACL that uses Monetize"

violation contains make_diag_full("pf-wafv2-cloudfront-only-features", "ERROR", name, _pf_waflib_path(i, array.concat(p, [kind, "ManagedRuleGroupConfigs", c, g, "ResponseInspection"])),
	"ResponseInspection is only available in web ACLs that protect CloudFront distributions; CreateWebACL fails with WAFInvalidOperationException \"Your request contains fields that belong to a feature you are not allowed to use.\"",
	_pf_wafcf_fix, _pf_wafcf_url) if {
	some [name, i, p, kind, body] in _pf_waflib_leaves
	kind == "ManagedRuleGroupStatement"
	_pf_waflib_scope(name) != "CLOUDFRONT"
	some c
	cfg := body.ManagedRuleGroupConfigs[c]
	some g in {"AWSManagedRulesATPRuleSet", "AWSManagedRulesACFPRuleSet"}
	cfg[g].ResponseInspection
}

violation contains make_diag_full("pf-wafv2-cloudfront-only-features", "ERROR", name, sprintf("Properties.Rules[%d].Action.Monetize", [i]),
	"Monetize is only available for CloudFront-scoped web ACLs; CreateWebACL fails with \"Monetization is not available for regional resources. Use CloudFront scope to configure monetization.\"",
	_pf_wafcf_fix, _pf_wafcf_url) if {
	some name in resources_of_type("AWS::WAFv2::WebACL")
	_pf_waflib_scope(name) != "CLOUDFRONT"
	rules := _pf_waflib_rules(name)
	some i
	rules[i].Action.Monetize
}

violation contains make_diag_full("pf-wafv2-cloudfront-only-features", "ERROR", name, sprintf("Properties.Rules[%d].Action.Monetize", [i]),
	"a Monetize rule needs MonetizationConfig on the web ACL; CreateWebACL fails with \"MonetizeAction requires MonetizationConfig to be configured on the WebACL.\"",
	_pf_wafcf_fix, _pf_wafcf_url) if {
	some name in resources_of_type("AWS::WAFv2::WebACL")
	rules := _pf_waflib_rules(name)
	some i
	rules[i].Action.Monetize
	object.get(input.resources[name].properties, "MonetizationConfig", "__pf_absent") == "__pf_absent"
}
