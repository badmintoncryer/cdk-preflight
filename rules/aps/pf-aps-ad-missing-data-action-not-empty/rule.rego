package cdk_preflight

import rego.v1

# MissingDataAction is a union of MarkAsAnomaly and Skip. The schema's oneOf
# stops both members at once, but not the zero-member side, and the L1 construct
# keeps an empty object: cdk renders { skip: undefined } as {}. Only a literally
# empty object is reported, so an Fn::If marker (one key) stays silent.
violation contains make_diag_full("pf-aps-ad-missing-data-action-not-empty", "ERROR", name,
	"Properties.MissingDataAction",
	"MissingDataAction is present but empty; CloudFormation's property validation fails with \"#/MissingDataAction: #: 0 subschemas matched instead of one\" before the handler runs",
	"Set exactly one of MarkAsAnomaly or Skip, or leave MissingDataAction out altogether",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-aps-anomalydetector-missingdataaction.html") if {
	some name in resources_of_type("AWS::APS::AnomalyDetector")
	mda := object.get(input.resources[name].properties, "MissingDataAction", null)
	is_object(mda)
	count(mda) == 0
}
