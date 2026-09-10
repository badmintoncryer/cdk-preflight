package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-hostedzone-name-wildcard-label", "ERROR", name,
	"Properties.Name",
	sprintf("hosted zone name %s starts with a wildcard label; a wildcard belongs in a record name, not in the zone name", [n]),
	"Create the zone for the concrete domain and use * in the record name",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html") if {
	some name in resources_of_type("AWS::Route53::HostedZone")
	n := _pf_r53z_str(_pf_r53z_props(name), "Name")
	startswith(n, "*")
}
