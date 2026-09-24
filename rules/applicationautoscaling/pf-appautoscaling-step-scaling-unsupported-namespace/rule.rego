package cdk_preflight

import rego.v1

_pf_aasstepns_unsupported := {"cassandra", "comprehend", "dynamodb", "elasticache", "kafka", "lambda", "neptune"}

violation contains make_diag_full("pf-appautoscaling-step-scaling-unsupported-namespace", "ERROR", name,
	"Properties.PolicyType",
	sprintf("PolicyType StepScaling is not supported for the '%s' namespace; PutScalingPolicy rejects the policy", [ns]),
	"Use PolicyType TargetTrackingScaling for these services, or attach the step policy to a namespace that supports it (ecs, ec2, appstream, rds, sagemaker, custom-resource)",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScalingPolicy.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	resolve(name, "Properties.PolicyType") == "StepScaling"
	ns := _pf_aaslib_namespace(name)
	ns in _pf_aasstepns_unsupported
}
