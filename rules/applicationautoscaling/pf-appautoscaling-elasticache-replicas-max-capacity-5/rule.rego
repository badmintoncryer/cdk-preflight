package cdk_preflight

import rego.v1

# ElastiCache allows at most 5 read replicas per node group, and
# RegisterScalableTarget enforces it before it looks the replication group up:
# "Maximum capacity cannot be greater than 5".
violation contains make_diag_full("pf-appautoscaling-elasticache-replicas-max-capacity-5", "ERROR", name,
	"Properties.MaxCapacity",
	sprintf("MaxCapacity %v is above the 5 replicas ElastiCache allows per node group; RegisterScalableTarget fails with \"Maximum capacity cannot be greater than 5\"", [mx]),
	"Lower MaxCapacity to 5 or less",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_RegisterScalableTarget.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	resolve(name, "Properties.ScalableDimension") == "elasticache:replication-group:Replicas"
	mx := to_number(resolve(name, "Properties.MaxCapacity"))
	mx > 5
}
