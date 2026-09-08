package cdk_preflight

import rego.v1

# The cluster carries a default namespace, so the service may omit its own.
_pf_ecs_clusterns(name) if {
	cl := resolve(name, "Properties.Cluster")
	input.resources[cl].resourceType == "AWS::ECS::Cluster"
	_pf_ecs_has(cl, "ServiceConnectDefaults")
}

violation contains make_diag_full("pf-ecs-svc-connect-without-namespace", "ERROR", name,
	"Properties.ServiceConnectConfiguration.Namespace",
	"Service Connect is enabled without a Namespace, and the cluster declares no ServiceConnectDefaults; CreateService fails with \"Namespace is missing\"",
	"Set ServiceConnectConfiguration.Namespace, or give the cluster ServiceConnectDefaults",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	scc := _pf_ecs_get(name, "ServiceConnectConfiguration")
	_pf_ecs_oget(scc, "Enabled") == true
	not _pf_ecs_ohas(scc, "Namespace")
	not _pf_ecs_clusterns(name)
}
