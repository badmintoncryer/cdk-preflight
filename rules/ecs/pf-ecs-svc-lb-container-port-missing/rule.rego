package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-lb-container-port-missing", "ERROR", name,
	"Properties.LoadBalancers",
	sprintf("The load balancer targets port %v of container '%s', which publishes no such port; CreateService fails with \"The container %s did not have a container port %v defined\"", [cp, cn, cn, cp]),
	"Add the port to the container PortMappings, or target a port the container already publishes",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	lbs := _pf_ecs_get(name, "LoadBalancers")
	is_array(lbs)
	some lb in lbs
	cn := object.get(lb, "ContainerName", null)
	_pf_ecs_lit(cn)
	cp := to_number(object.get(lb, "ContainerPort", null))
	td := _pf_ecs_reftd(name, "Properties.TaskDefinition")
	some c in _pf_ecs_containers(td)
	object.get(c.value, "Name", null) == cn
	pms := _pf_ecs_cget(c, "PortMappings")
	is_array(pms)
	not cp in {to_number(object.get(pm, "ContainerPort", null)) | some pm in pms}
}
