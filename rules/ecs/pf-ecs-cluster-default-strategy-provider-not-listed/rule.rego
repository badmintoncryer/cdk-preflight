package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-cluster-default-strategy-provider-not-listed", "ERROR", name,
	"Properties.DefaultCapacityProviderStrategy",
	sprintf("The default strategy uses the capacity provider '%s', which the cluster does not list in CapacityProviders; CreateCluster fails with \"The specified capacity provider strategy cannot contain a capacity provider that is not associated with the cluster\"", [cp]),
	"Add the capacity provider to CapacityProviders",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::ECS::Cluster")
	listed := _pf_ecs_get(name, "CapacityProviders")
	is_array(listed)
	some s in flatten_list(name, "Properties.DefaultCapacityProviderStrategy")
	cp := object.get(s.value, "CapacityProvider", null)
	_pf_ecs_lit(cp)
	not cp in {x | some x in listed; _pf_ecs_lit(x)}
}
