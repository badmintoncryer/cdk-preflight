package cdk_preflight

import rego.v1

_pf_aps_ade_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-aps-anomalydetector.html"

_pf_aps_ade_fix := "Use an evaluation interval between 30 and 86400 seconds"

# The CloudFormation schema has no Minimum or Maximum for this property (the
# sibling SampleSize does, and the engine stops 100 there), so both ends of the
# service's range are a gap.
violation contains make_diag_full("pf-aps-ad-evaluation-interval-range", "ERROR", name,
	"Properties.EvaluationIntervalInSeconds",
	sprintf("EvaluationIntervalInSeconds is %v; the AnomalyDetector handler fails with \"InvalidParameter: 1 validation error(s) found. minimum field value of 30, CreateAnomalyDetectorInput.EvaluationIntervalInSeconds.\"", [n]),
	_pf_aps_ade_fix, _pf_aps_ade_url) if {
	some name in resources_of_type("AWS::APS::AnomalyDetector")
	n := _pf_aps_num(name, "Properties.EvaluationIntervalInSeconds")
	n < 30
}

violation contains make_diag_full("pf-aps-ad-evaluation-interval-range", "ERROR", name,
	"Properties.EvaluationIntervalInSeconds",
	sprintf("EvaluationIntervalInSeconds is %v; CreateAnomalyDetector fails with \"Invalid evaluationIntervalInSeconds: Member must have value less than or equal to 86400\"", [n]),
	_pf_aps_ade_fix, _pf_aps_ade_url) if {
	some name in resources_of_type("AWS::APS::AnomalyDetector")
	n := _pf_aps_num(name, "Properties.EvaluationIntervalInSeconds")
	n > 86400
}
