package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-ruletype-enum", "ERROR", name,
	"Properties.RuleType",
	sprintf("RuleType is '%s'; Route 53 Resolver only accepts FORWARD, SYSTEM, RECURSIVE and DELEGATE", [t]),
	"Set RuleType to FORWARD, SYSTEM, RECURSIVE or DELEGATE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-resolverrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	t := _pf_r53r_str(p, "RuleType")
	not t in {"FORWARD", "SYSTEM", "RECURSIVE", "DELEGATE"}
}
