package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-targetip-protocol-enum", "ERROR", name,
	"Properties.TargetIps",
	sprintf("TargetIps declares Protocol '%s'; Route 53 Resolver only accepts Do53, DoH and DoH-FIPS", [v]),
	"Use Do53, DoH or DoH-FIPS",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-resolverrule-targetaddress.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	some t in _pf_r53r_arr(p, "TargetIps")
	v := _pf_r53r_str(t, "Protocol")
	not v in {"Do53", "DoH", "DoH-FIPS"}
}
