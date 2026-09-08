package cdk_preflight

import rego.v1

# A literal stage name must match a stage the template creates - either an
# explicit Stage or the one a Deployment creates through StageName. A Ref
# resolves to a logical id, which is what `input.resources` filters out.
_pf_apgupas_names contains n if {
	some s in resources_of_type("AWS::ApiGateway::Stage")
	n := resolve(s, "Properties.StageName")
	is_string(n)
}

# Only judge stages of an API this template creates: a Ref inside a list item
# surfaces as {"__ref": "<logical id>"}, and an imported id is skipped.
_pf_apgupas_own_api(a) if {
	ref := a.ApiId.__ref
	ref in resources_of_type("AWS::ApiGateway::RestApi")
}

_pf_apgupas_names contains n if {
	some d in resources_of_type("AWS::ApiGateway::Deployment")
	n := resolve(d, "Properties.StageName")
	is_string(n)
}

violation contains make_diag_full("pf-apigw-usage-plan-api-stage-exists", "ERROR", name,
	"Properties.ApiStages",
	sprintf("ApiStages references stage '%s', which no Stage or Deployment in this template creates; the usage plan create fails with \"API Stage not found\"", [st]),
	"Reference the stage by { \"Ref\": \"<Stage logical id>\" }, or use the StageName the template actually deploys",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-usageplan-apistage.html") if {
	some name in resources_of_type("AWS::ApiGateway::UsagePlan")
	some item in flatten_list(name, "Properties.ApiStages")
	a := item.value
	is_object(a)
	_pf_apgupas_own_api(a)
	st := a.Stage
	is_string(st)
	not input.resources[st]
	not st in _pf_apgupas_names
}
