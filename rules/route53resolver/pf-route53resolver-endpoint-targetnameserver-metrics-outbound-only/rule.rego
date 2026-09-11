package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-targetnameserver-metrics-outbound-only", "ERROR", name,
	"Properties.TargetNameServerMetricsEnabled",
	"the inbound endpoint sets TargetNameServerMetricsEnabled; target name server metrics are outbound only",
	"Drop TargetNameServerMetricsEnabled, or move it to an outbound endpoint",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-resolverendpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	_pf_r53r_get(p, "TargetNameServerMetricsEnabled") == true
	_pf_r53r_str(p, "Direction") == "INBOUND"
}
