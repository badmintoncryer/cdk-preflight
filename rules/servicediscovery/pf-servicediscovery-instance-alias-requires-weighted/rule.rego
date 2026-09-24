package cdk_preflight

import rego.v1

# RoutingPolicy defaults to MULTIVALUE, so the omitted case has to fire too.
violation contains make_diag_full("pf-servicediscovery-instance-alias-requires-weighted", "ERROR", name,
	"Properties.InstanceAttributes.AWS_ALIAS_DNS_NAME",
	sprintf("This instance registers an ELB alias, but service '%v' routes %v; RegisterInstance fails with \"ALIAS instance can be registered only in services with WEIGHTED routing policy\"", [svc, _pf_sd_routing(svc)]),
	"Set DnsConfig.RoutingPolicy to WEIGHTED on the service, or register an IP address instead",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_DnsConfig.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	svc := _pf_sd_inst_svc(name)
	_pf_sd_has_attr(name, "AWS_ALIAS_DNS_NAME")
	_pf_sd_routing(svc) != "WEIGHTED"
}
