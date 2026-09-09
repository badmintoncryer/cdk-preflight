package cdk_preflight

import rego.v1

# The tier lives on the user pool and the event source on the log delivery
# resource; ESSENTIALS is the default when UserPoolTier is omitted.

_pf_cglduaet_tier(pool) := t if {
	t := _pf_coglib_g1(pool, "UserPoolTier")
	is_string(t)
	t != "__pf_absent"
}

_pf_cglduaet_tier(pool) := "ESSENTIALS" if _pf_coglib_absent(_pf_coglib_g1(pool, "UserPoolTier"))

violation contains make_diag_full("pf-cognito-log-delivery-user-auth-events-tier", "ERROR", name,
	sprintf("Properties.LogConfigurations.%d.EventSource", [c.index]),
	sprintf("userAuthEvents logging on a %v pool; the log delivery call fails with \"The following feature is not available for the %v pricing tier configured: Log Streaming\"", [tier, tier]),
	"Set UserPoolTier: PLUS on the pool, or log only userNotification events",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-logdeliveryconfiguration.html") if {
	some name in resources_of_type("AWS::Cognito::LogDeliveryConfiguration")
	pool := resolve(name, "Properties.UserPoolId")
	pool in resources_of_type("AWS::Cognito::UserPool")
	tier := _pf_cglduaet_tier(pool)
	tier != "PLUS"
	some c in flatten_list(name, "Properties.LogConfigurations")
	_pf_coglib_at(c.value, "EventSource") == "userAuthEvents"
}
