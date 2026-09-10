package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-hostedzone-querylogging-private-zone", "ERROR", name,
	"Properties.QueryLoggingConfig",
	"the hosted zone is private (it has VPCs) and also asks for query logging, which Route 53 offers on public zones only",
	"Drop QueryLoggingConfig, or make the zone public",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html") if {
	some name in resources_of_type("AWS::Route53::HostedZone")
	p := _pf_r53z_props(name)
	_pf_r53z_has(p, "QueryLoggingConfig")
	v := object.get(p, "VPCs", [])
	count(v) > 0
}
