package cdk_preflight

import rego.v1

# One service check, three messages: GITHUB_HMAC takes only SecretToken, IP takes
# only AllowedIPRange, UNAUTHENTICATED takes neither.
violation contains make_diag_full("pf-codepipeline-webhook-authentication-configuration", "ERROR", name,
	"Properties.AuthenticationConfiguration",
	sprintf("Authentication %v takes only '%v' but AuthenticationConfiguration also sets '%v'; PutWebhook fails with \"InvalidWebhookAuthenticationParametersException: Optional['authenticationConfig' should contain only one property: '%v']\"", [auth, want, extra, want]),
	"Set only the AuthenticationConfiguration property the Authentication mode takes",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_PutWebhook.html") if {
	some name in resources_of_type("AWS::CodePipeline::Webhook")
	p := _pf_cplib_props(name)
	auth := _pf_cplib_get(p, "Authentication")
	_pf_cplib_lit(auth)
	want := _pf_cplib_webhook_auth_key[auth]
	cfg := object.get(p, "AuthenticationConfiguration", {})
	_pf_cplib_plain(cfg)
	some extra, _ in cfg
	extra != want
}

# ... and the property it does take is mandatory.
violation contains make_diag_full("pf-codepipeline-webhook-authentication-configuration", "ERROR", name,
	"Properties.AuthenticationConfiguration",
	sprintf("Authentication %v requires AuthenticationConfiguration.%v; PutWebhook fails with \"InvalidWebhookAuthenticationParametersException: Optional['authenticationConfig' should contain only one property: '%v']\"", [auth, want, want]),
	"Set the AuthenticationConfiguration property the Authentication mode requires",
	"https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_PutWebhook.html") if {
	some name in resources_of_type("AWS::CodePipeline::Webhook")
	p := _pf_cplib_props(name)
	auth := _pf_cplib_get(p, "Authentication")
	_pf_cplib_lit(auth)
	want := _pf_cplib_webhook_auth_key[auth]
	want != ""
	cfg := object.get(p, "AuthenticationConfiguration", {})
	_pf_cplib_plain(cfg)
	_pf_cplib_absent(cfg, want)
}
