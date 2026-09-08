package cdk_preflight

import rego.v1

# Only the plainly-not-a-document case is judged; a policy written as an object
# is rendered as JSON by CloudFormation.
violation contains make_diag_full("pf-apigw-rest-api-policy-document", "ERROR", name,
	"Properties.Policy",
	sprintf("Policy is the string '%s', not a policy document; the API create fails with \"Invalid policy document. Please check the policy syntax and ensure that Principals are valid.\"", [pol]),
	"Write the resource policy as a JSON object (or a JSON document string starting with {)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-restapi.html") if {
	some name in resources_of_type("AWS::ApiGateway::RestApi")
	pol := resolve(name, "Properties.Policy")
	is_string(pol)
	not input.resources[pol]
	not startswith(trim_space(pol), "{")
}
