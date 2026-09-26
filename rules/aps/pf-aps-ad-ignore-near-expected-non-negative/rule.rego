package cdk_preflight

import rego.v1

# The CloudFormation schema has no Minimum for Amount or Ratio on either
# IgnoreNearExpectedFromAbove or IgnoreNearExpectedFromBelow; the service floors
# both at 0.
violation contains make_diag_full("pf-aps-ad-ignore-near-expected-non-negative", "ERROR", name,
	"Properties.Configuration.RandomCutForest",
	sprintf("%v.%v is %v; CreateAnomalyDetector fails with \"Invalid configuration.randomCutForest.ignoreNearExpectedFromAbove.ratio: Member must have value greater than or equal to 0\"", [t[0], t[1], t[2]]),
	"Use an amount or ratio of 0 or more",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-aps-anomalydetector-ignorenearexpected.html") if {
	some name in resources_of_type("AWS::APS::AnomalyDetector")
	some t in _pf_aps_ad_ignore_near(name)
	t[2] < 0
}
