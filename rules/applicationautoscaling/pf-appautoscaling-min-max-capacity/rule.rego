package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appautoscaling-min-max-capacity", "ERROR", name,
	"Properties.MinCapacity",
	sprintf("MinCapacity %v is above MaxCapacity %v; RegisterScalableTarget fails with \"Maximum capacity cannot be less than minimum capacity\"", [mn, mx]),
	"Lower MinCapacity to MaxCapacity or below (equal values are accepted)",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_RegisterScalableTarget.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	mn := to_number(resolve(name, "Properties.MinCapacity"))
	mx := to_number(resolve(name, "Properties.MaxCapacity"))
	mn > mx
}
