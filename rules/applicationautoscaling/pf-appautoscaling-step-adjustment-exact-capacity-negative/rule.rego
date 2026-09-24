package cdk_preflight

import rego.v1

# With AdjustmentType ExactCapacity the ScalingAdjustment is the capacity to
# scale to, not a delta, so a negative value has no meaning.
violation contains make_diag_full("pf-appautoscaling-step-adjustment-exact-capacity-negative", "ERROR", name,
	sprintf("Properties.StepScalingPolicyConfiguration.StepAdjustments.%d.ScalingAdjustment", [i]),
	sprintf("AdjustmentType is ExactCapacity, so ScalingAdjustment %v is a capacity, not a delta; PutScalingPolicy fails with \"Scaling adjustment cannot be less than 0 when adjustment type is ExactCapacity\"", [n]),
	"Use a capacity of 0 or more, or switch AdjustmentType to ChangeInCapacity to scale by a delta",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_StepAdjustment.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	resolve(name, "Properties.StepScalingPolicyConfiguration.AdjustmentType") == "ExactCapacity"
	some i, a in _pf_aaslib_steps(name)
	n := to_number(object.get(a, "ScalingAdjustment", "__pf_absent"))
	n < 0
}
