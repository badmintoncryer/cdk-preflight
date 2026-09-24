package cdk_preflight

import rego.v1

_pf_cfgrar_err := "the remediation create fails: automatic remediation has to know how often to retry"

violation contains make_diag_full("pf-config-remediation-automatic-requires-attempts-and-retry", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("Automatic is true but %s is not set; %s", [k, _pf_cfgrar_err]),
	"Set both MaximumAutomaticAttempts and RetryAttemptSeconds, or set Automatic to false",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-config-remediationconfiguration.html") if {
	some name in resources_of_type("AWS::Config::RemediationConfiguration")
	resolve(name, "Properties.Automatic") == true
	some k in {"MaximumAutomaticAttempts", "RetryAttemptSeconds"}
	not _pf_cfglib_present(_pf_cfglib_props(name), k)
}
