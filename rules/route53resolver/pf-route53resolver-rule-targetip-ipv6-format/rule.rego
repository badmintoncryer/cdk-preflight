package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-targetip-ipv6-format", "ERROR", name,
	"Properties.TargetIps",
	sprintf("TargetIps contains Ipv6 '%s', which is not a valid IPv6 address", [v]),
	"Use a colon-separated IPv6 address of 7 to 39 characters",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-resolverrule-targetaddress.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	some t in _pf_r53r_arr(p, "TargetIps")
	v := _pf_r53r_str(t, "Ipv6")
	not _pf_r53r_ipv6(v)
}
