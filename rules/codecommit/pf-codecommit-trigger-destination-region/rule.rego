package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codecommit-trigger-destination-region", "ERROR", name,
	sprintf("Properties.Triggers.%d.DestinationArn", [i]),
	sprintf("The trigger destination is in '%s' but the repository deploys to '%s'; the handler's PutRepositoryTriggers fails with \"Repository trigger destination arn must be for the same region as your repository\"", [dr, region]),
	"Point the trigger at a topic or function in the deploy region",
	"https://docs.aws.amazon.com/codecommit/latest/APIReference/API_PutRepositoryTriggers.html") if {
	some name in resources_of_type("AWS::CodeCommit::Repository")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	some i, t in _pf_cclib_triggers(name)
	is_object(t)
	parts := _pf_cclib_arn(object.get(t, "DestinationArn", ""))
	dr := parts[3]
	dr != ""
	dr != region
}
