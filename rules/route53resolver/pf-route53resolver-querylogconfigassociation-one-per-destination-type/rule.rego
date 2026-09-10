package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-querylogconfigassociation-one-per-destination-type", "ERROR", name,
	"Properties.ResourceId",
	"another query log association in this template sends the same VPC to the same destination type",
	"Keep one association per VPC and destination type",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logging-configurations-managing.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverQueryLoggingConfigAssociation")
	p := _pf_r53r_props(name)
	k := sprintf("%s|%s", [_pf_r53r_key(p, "ResourceId"), _pf_r53r_qlca_dest(p)])
	dup := [1 |
		some o in resources_of_type("AWS::Route53Resolver::ResolverQueryLoggingConfigAssociation")
		q := _pf_r53r_props(o)
		sprintf("%s|%s", [_pf_r53r_key(q, "ResourceId"), _pf_r53r_qlca_dest(q)]) == k
	]
	count(dup) > 1
}
