package cdk_preflight

import rego.v1

# "For predefined metric type DynamoDBReadCapacityUtilization, target value must
# be between '10.0' and '90.0'". Closed interval: 10 and 90 deploy, 9.9 and 90.1
# do not. The DynamoDB developer guide's 20-90% is advice, not the limit.
_pf_aasdtv_types := {"DynamoDBReadCapacityUtilization", "DynamoDBWriteCapacityUtilization"}

_pf_aasdtv_cfg(name) := c if {
	p := input.resources[name].properties
	c := object.get(p, "TargetTrackingScalingPolicyConfiguration", "__pf_absent")
	is_object(c)
}

_pf_aasdtv_in_range(v) if {
	v >= 10
	v <= 90
}

violation contains make_diag_full("pf-appautoscaling-dynamodb-target-value-range", "ERROR", name,
	"Properties.TargetTrackingScalingPolicyConfiguration.TargetValue",
	sprintf("TargetValue %v is outside 10-90 for predefined metric type '%s'; PutScalingPolicy fails with \"target value must be between '10.0' and '90.0'\"", [tv, mt]),
	"Set TargetValue between 10 and 90 (both accepted)",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/AutoScaling.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	c := _pf_aasdtv_cfg(name)
	mt := object.get(object.get(c, "PredefinedMetricSpecification", {}), "PredefinedMetricType", "__pf_absent")
	mt in _pf_aasdtv_types
	tv := to_number(object.get(c, "TargetValue", "__pf_absent"))
	not _pf_aasdtv_in_range(tv)
}
