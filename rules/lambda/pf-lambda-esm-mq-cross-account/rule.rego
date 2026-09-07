package cdk_preflight

import rego.v1

_pf_lemca_fix := "Point EventSourceArn at a broker in the deploy account"

_pf_lemca_url := "https://docs.aws.amazon.com/lambda/latest/dg/with-mq.html"

violation contains make_diag_full("pf-lambda-esm-mq-cross-account", "ERROR", name,
	"Properties.EventSourceArn",
	sprintf("the broker belongs to account %v but the stack deploys to account %v; Amazon MQ event sources are not cross-account", [parts[4], account]),
	_pf_lemca_fix, _pf_lemca_url) if {
	account := data.cdk_preflight.deploy_account
	some name in _pf_lam_esm
	parts := _pf_lam_arn(resolve(name, "Properties.EventSourceArn"))
	parts[2] == "mq"
	parts[4] != account
}
