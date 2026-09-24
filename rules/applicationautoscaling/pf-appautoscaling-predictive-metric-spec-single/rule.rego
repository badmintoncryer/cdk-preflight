package cdk_preflight

import rego.v1

# MetricSpecifications is a list in the API but the service accepts exactly one
# element; an empty list and a second element both draw the same sentence. The
# absent key is not judged here — the registry schema already answers that with
# F3003.
violation contains make_diag_full("pf-appautoscaling-predictive-metric-spec-single", "ERROR", name,
	"Properties.PredictiveScalingPolicyConfiguration.MetricSpecifications",
	sprintf("MetricSpecifications has %d entries; PutScalingPolicy fails with \"You must specify one metric specification.\"", [n]),
	"Keep the one metric specification the policy should forecast on and split the rest into their own policies",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredictiveScalingPolicyConfiguration.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	cfg := object.get(_pf_aaslib_props(name), "PredictiveScalingPolicyConfiguration", "__pf_absent")
	is_object(cfg)
	specs := object.get(cfg, "MetricSpecifications", "__pf_absent")
	is_array(specs)
	n := count(specs)
	n != 1
}
