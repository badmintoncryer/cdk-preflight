package cdk_preflight

import rego.v1

# RegisterScalableTarget accepts MinCapacity 0 only for the namespaces the API
# reference lists (appstream, custom-resource, ec2, ecs, elasticmapreduce,
# lambda, rds, sagemaker). The six below answer "Minimum capacity cannot be less
# than 1" instead. workspaces is left out on purpose: WorkSpaces Pools is closed
# to new customers, so the namespace cannot be reached at all any more.
_pf_aasmincap_needs_one := {"cassandra", "comprehend", "dynamodb", "elasticache", "kafka", "neptune"}

violation contains make_diag_full("pf-appautoscaling-min-capacity-zero-namespace", "ERROR", name,
	"Properties.MinCapacity",
	sprintf("ServiceNamespace '%s' does not accept MinCapacity %v; RegisterScalableTarget fails with \"Minimum capacity cannot be less than 1\"", [ns, mn]),
	"Set MinCapacity to 1 or more; only appstream, custom-resource, ec2, ecs, elasticmapreduce, lambda, rds and sagemaker scale to 0",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_RegisterScalableTarget.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	ns := resolve(name, "Properties.ServiceNamespace")
	ns in _pf_aasmincap_needs_one
	mn := to_number(resolve(name, "Properties.MinCapacity"))
	mn < 1
}
