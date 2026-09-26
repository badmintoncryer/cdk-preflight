package cdk_preflight

import rego.v1

# IgnoreNearExpected is a union of Amount and Ratio. The schema's oneOf stops
# both members at once, but not the zero-member side, and the L1 construct keeps
# an empty object: cdk renders { ratio: undefined } as {}. Only a literally empty
# object is reported, so an Fn::If marker (one key) stays silent.
violation contains make_diag_full("pf-aps-ad-ignore-near-expected-not-empty", "ERROR", name,
	"Properties.Configuration.RandomCutForest",
	sprintf("%v is present but empty; CloudFormation's property validation fails with \"#/Configuration/RandomCutForest/%v: #: 0 subschemas matched instead of one\" before the handler runs", [prop, prop]),
	"Set exactly one of Amount or Ratio, or leave the block out altogether",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-aps-anomalydetector-ignorenearexpected.html") if {
	some name in resources_of_type("AWS::APS::AnomalyDetector")
	some prop in ["IgnoreNearExpectedFromAbove", "IgnoreNearExpectedFromBelow"]
	block := object.get(_pf_aps_ad_rcf(name), prop, null)
	is_object(block)
	count(block) == 0
}
