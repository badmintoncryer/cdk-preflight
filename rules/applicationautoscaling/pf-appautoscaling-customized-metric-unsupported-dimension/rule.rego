package cdk_preflight

import rego.v1

# "Scalable dimension dynamodb:table:ReadCapacityUnits does not support
# CustomizedMetricSpecification." Only the two DynamoDB table dimensions are
# listed here: those are the ones the bench measured, and guessing at the other
# dimensions would risk reporting a combination the service accepts.
_pf_aascmu_dims := {"dynamodb:table:ReadCapacityUnits", "dynamodb:table:WriteCapacityUnits"}

_pf_aascmu_spec(name) := s if {
	p := input.resources[name].properties
	c := object.get(p, "TargetTrackingScalingPolicyConfiguration", {})
	s := object.get(c, "CustomizedMetricSpecification", "__pf_absent")
	is_object(s)
}

violation contains make_diag_full("pf-appautoscaling-customized-metric-unsupported-dimension", "ERROR", name,
	"Properties.TargetTrackingScalingPolicyConfiguration.CustomizedMetricSpecification",
	sprintf("Scalable dimension '%s' takes predefined metrics only; PutScalingPolicy fails with \"Scalable dimension %s does not support CustomizedMetricSpecification.\"", [dim, dim]),
	"Use PredefinedMetricSpecification with DynamoDBReadCapacityUtilization or DynamoDBWriteCapacityUtilization",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_CustomizedMetricSpecification.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	dim := _pf_aaslib_dimension(name)
	dim in _pf_aascmu_dims
	_pf_aascmu_spec(name)
}
