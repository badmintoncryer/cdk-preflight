package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-connect-port-name-missing", "ERROR", name,
	"Properties.ServiceConnectConfiguration.Services",
	sprintf("Service Connect exposes the port name '%s', which the referenced task definition does not declare; CreateService fails with \"portName(%s) does not refer to any named PortMapping in the container definitions\"", [pn, pn]),
	"Name the port mapping in the task definition, or point PortName at an existing one",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	scc := _pf_ecs_get(name, "ServiceConnectConfiguration")
	svcs := _pf_ecs_oget(scc, "Services")
	is_array(svcs)
	some s in svcs
	pn := object.get(s, "PortName", null)
	_pf_ecs_lit(pn)
	td := _pf_ecs_reftd(name, "Properties.TaskDefinition")
	not pn in {n | some pm in _pf_ecs_portmappings(td); n := object.get(pm, "Name", null)}
}
