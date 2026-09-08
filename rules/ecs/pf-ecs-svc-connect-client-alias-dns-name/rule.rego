package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-connect-client-alias-dns-name", "ERROR", name,
	"Properties.ServiceConnectConfiguration.Services",
	sprintf("The Service Connect client alias '%s' is not a valid DNS name; CreateService fails with \"The DNS name that you provided is invalid\"", [dn]),
	"Use a DNS-safe name (letters, digits, hyphen and dot)",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	scc := _pf_ecs_get(name, "ServiceConnectConfiguration")
	svcs := _pf_ecs_oget(scc, "Services")
	is_array(svcs)
	some s in svcs
	some ca in object.get(s, "ClientAliases", [])
	dn := object.get(ca, "DnsName", null)
	_pf_ecs_lit(dn)
	not regex.match("^[A-Za-z0-9]([A-Za-z0-9.-]{0,125}[A-Za-z0-9])?$", dn)
}
