package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-proxy-configuration-missing-required-props", "ERROR", name,
	"Properties.ProxyConfiguration.ProxyConfigurationProperties",
	sprintf("The APPMESH ProxyConfiguration does not set %s; RegisterTaskDefinition fails with \"Ingress port not found\" (or the equivalent for the other keys)", [req]),
	"Add ProxyIngressPort, ProxyEgressPort, AppPorts and EgressIgnoredIPs to ProxyConfigurationProperties",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	pc := _pf_ecs_get(name, "ProxyConfiguration")
	object.get(pc, "Type", "APPMESH") == "APPMESH"
	given := {n | some p in object.get(pc, "ProxyConfigurationProperties", []); n := object.get(p, "Name", null)}
	some req in {"ProxyIngressPort", "ProxyEgressPort", "AppPorts", "EgressIgnoredIPs"}
	not req in given
}
