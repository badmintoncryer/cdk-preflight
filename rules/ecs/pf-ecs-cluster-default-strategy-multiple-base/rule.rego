package cdk_preflight

import rego.v1

# CreateCluster says "a base value defined", but an explicit Base: 0 is accepted
# next to a Base above zero (bench 2026-11-25, issue #394), so only entries with
# Base above zero count.

violation contains make_diag_full("pf-ecs-cluster-default-strategy-multiple-base", "ERROR", name,
	"Properties.DefaultCapacityProviderStrategy",
	"More than one entry of DefaultCapacityProviderStrategy sets Base above zero; CreateCluster fails with \"The specified capacity provider strategy contains multiple capacity providers with a base value defined\"",
	"Keep Base above zero on a single capacity provider",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::ECS::Cluster")
	st := _pf_ecs_get(name, "DefaultCapacityProviderStrategy")
	is_array(st)
	count([x | some x in st; _pf_tonum(_pf_ecs_oget(x, "Base")) > 0]) > 1
}
