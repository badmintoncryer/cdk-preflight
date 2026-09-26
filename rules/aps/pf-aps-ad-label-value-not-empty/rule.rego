package cdk_preflight

import rego.v1

# The CloudFormation schema allows a zero-length Value (Minimum: 0); the service
# requires at least one character.
violation contains make_diag_full("pf-aps-ad-label-value-not-empty", "ERROR", name,
	"Properties.Labels",
	sprintf("label \"%v\" has an empty Value; CreateAnomalyDetector fails with \"Invalid labels: Map value must satisfy constraint: [Member must have length less than or equal to 7168, Member must have length greater than or equal to 1]\"", [k]),
	"Give the label a non-empty value, or drop the label",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-aps-anomalydetector-label.html") if {
	some name in resources_of_type("AWS::APS::AnomalyDetector")
	some label in _pf_aps_ad_labels(name)
	k := object.get(label, "Key", null)
	is_string(k)
	v := object.get(label, "Value", null)
	is_string(v)
	v == ""
}
