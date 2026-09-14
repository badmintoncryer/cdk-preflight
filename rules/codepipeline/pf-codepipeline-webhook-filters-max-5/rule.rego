package cdk_preflight

import rego.v1

# 5 filters per webhook. The raw CloudFormation schema carries no maxItems here,
# so the stack reaches PutWebhook and the service names the limit.
violation contains make_diag_full("pf-codepipeline-webhook-filters-max-5", "ERROR", name,
	"Properties.Filters",
	sprintf("the webhook declares %d filters; PutWebhook fails with \"failed to satisfy constraint: Member must have length less than or equal to 5\"", [n]),
	"Keep the webhook to 5 filters or fewer",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_PutWebhook.html") if {
	some name in resources_of_type("AWS::CodePipeline::Webhook")
	n := count(object.get(_pf_cplib_props(name), "Filters", []))
	n > 5
}
