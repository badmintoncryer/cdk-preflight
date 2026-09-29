package cdk_preflight

import rego.v1

_pf_eb_opt_secrets_arn_service_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-secrets-arn-service", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Environment secret %s has the value '%s', which is not a Secrets Manager or Systems Manager Parameter Store ARN; Elastic Beanstalk rejects it", [o.nm, o.s]),
	"Use the ARN of a Secrets Manager secret (arn:aws:secretsmanager:...) or an SSM parameter (arn:aws:ssm:...)", _pf_eb_opt_secrets_arn_service_url) if {
	o := _pf_eblib_opt[_]
	o.ns == "aws:elasticbeanstalk:application:environmentsecrets"
	not regex.match(`^arn:aws[a-z-]*:(secretsmanager|ssm):`, o.s)
}
