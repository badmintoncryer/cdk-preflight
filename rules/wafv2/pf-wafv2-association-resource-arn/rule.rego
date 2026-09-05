package cdk_preflight

import rego.v1

_pf_wafara_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_AssociateWebACL.html"

_pf_wafara_fix := "Associate an ALB (loadbalancer/app/), REST API stage, AppSync API, Cognito user pool, App Runner service, Verified Access instance or AgentCore gateway from the same account and region; CloudFront distributions take the web ACL through DistributionConfig.WebACLId instead, and Amplify apps only through a us-east-1 stack"

_pf_wafara_ok := {
	"^arn:[^:]+:elasticloadbalancing:[^:]*:[^:]*:loadbalancer/app/[^/]+/[^/]+$",
	"^arn:[^:]+:apigateway:[^:]*::/restapis/[^/]+/stages/[^/]+$",
	"^arn:[^:]+:appsync:[^:]*:[^:]*:apis/[^/]+$",
	"^arn:[^:]+:cognito-idp:[^:]*:[^:]*:userpool/[^/]+$",
	"^arn:[^:]+:apprunner:[^:]*:[^:]*:service/[^/]+/[^/]+$",
	"^arn:[^:]+:ec2:[^:]*:[^:]*:verified-access-instance/[^/]+$",
	"^arn:[^:]+:bedrock-agentcore:[^:]*:[^:]*:gateway/[^/]+$",
	"^arn:[^:]+:amplify:[^:]*:[^:]*:apps/[^/]+$",
}

_pf_wafara_supported(s) if {
	some re in _pf_wafara_ok
	regex.match(re, s)
}

_pf_wafara_msg := "AssociateWebACL fails with \"The ARN isn't valid. A valid ARN begins with arn: and includes other information separated by colons or slashes.\""

_pf_wafara_lit(name) := _pf_waflib_lit(name, "Properties.ResourceArn")

violation contains make_diag_full("pf-wafv2-association-resource-arn", "ERROR", name, "Properties.ResourceArn",
	sprintf("'%s' is not an ARN of a resource type that AssociateWebACL accepts (ALB, REST API stage, AppSync, Cognito, App Runner, Verified Access, Amplify, AgentCore gateway); %s", [s, _pf_wafara_msg]),
	_pf_wafara_fix, _pf_wafara_url) if {
	some name in resources_of_type("AWS::WAFv2::WebACLAssociation")
	s := _pf_wafara_lit(name)
	not _pf_wafara_supported(s)
}

# Needs the deploy environment (enforce mode only).
violation contains make_diag_full("pf-wafv2-association-resource-arn", "ERROR", name, "Properties.ResourceArn",
	sprintf("resource is in region '%s' but the association deploys to '%s'; %s", [parts[3], region, _pf_wafara_msg]),
	_pf_wafara_fix, _pf_wafara_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::WAFv2::WebACLAssociation")
	s := _pf_wafara_lit(name)
	_pf_wafara_supported(s)
	parts := _pf_waflib_arn(s)
	parts[3] != region
	not regex.match("^arn:[^:]+:amplify:", s)
}

violation contains make_diag_full("pf-wafv2-association-resource-arn", "ERROR", name, "Properties.ResourceArn",
	sprintf("Amplify apps can only be associated from us-east-1, but this stack deploys to '%s'; AssociateWebACL fails with \"The resource is not supported in current region\"", [region]),
	_pf_wafara_fix, _pf_wafara_url) if {
	region := data.cdk_preflight.deploy_region
	region != "us-east-1"
	some name in resources_of_type("AWS::WAFv2::WebACLAssociation")
	s := _pf_wafara_lit(name)
	regex.match("^arn:[^:]+:amplify:", s)
}

violation contains make_diag_full("pf-wafv2-association-resource-arn", "ERROR", name, "Properties.ResourceArn",
	sprintf("resource belongs to account %s but the association deploys to account %s; AssociateWebACL fails with AccessDenied", [parts[4], account]),
	_pf_wafara_fix, _pf_wafara_url) if {
	account := data.cdk_preflight.deploy_account
	some name in resources_of_type("AWS::WAFv2::WebACLAssociation")
	s := _pf_wafara_lit(name)
	_pf_wafara_supported(s)
	parts := _pf_waflib_arn(s)
	parts[4] != ""
	parts[4] != account
}

# in-template references
_pf_wafara_raw(name) := input.resources[name].properties.ResourceArn

_pf_wafara_bad_types := {"AWS::CloudFront::Distribution", "AWS::ElasticLoadBalancing::LoadBalancer", "AWS::ApiGatewayV2::Api", "AWS::ApiGatewayV2::Stage", "AWS::Lambda::Function", "AWS::ApiGateway::RestApi"}

violation contains make_diag_full("pf-wafv2-association-resource-arn", "ERROR", name, "Properties.ResourceArn",
	sprintf("references %s (%s), which AssociateWebACL does not accept; %s", [x, t, _pf_wafara_msg]),
	_pf_wafara_fix, _pf_wafara_url) if {
	some name in resources_of_type("AWS::WAFv2::WebACLAssociation")
	x := _pf_waflib_getatt(_pf_wafara_raw(name))
	some t in _pf_wafara_bad_types
	x in resources_of_type(t)
}

violation contains make_diag_full("pf-wafv2-association-resource-arn", "ERROR", name, "Properties.ResourceArn",
	sprintf("references load balancer %s of Type '%s'; only application load balancers can be associated; %s", [x, t, _pf_wafara_msg]),
	_pf_wafara_fix, _pf_wafara_url) if {
	some name in resources_of_type("AWS::WAFv2::WebACLAssociation")
	x := _pf_waflib_getatt(_pf_wafara_raw(name))
	x in resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")
	t := resolve(x, "Properties.Type")
	t != "application"
}

violation contains make_diag_full("pf-wafv2-association-resource-arn", "ERROR", name, "Properties.ResourceArn",
	sprintf("Ref %s returns the stage name, not an ARN; build the ARN with Fn::Sub arn:${AWS::Partition}:apigateway:${AWS::Region}::/restapis/${RestApi}/stages/${%s}", [x, x]),
	_pf_wafara_fix, _pf_wafara_url) if {
	some name in resources_of_type("AWS::WAFv2::WebACLAssociation")
	x := _pf_waflib_ref(_pf_wafara_raw(name))
	x in resources_of_type("AWS::ApiGateway::Stage")
}
