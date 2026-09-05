package cdk_preflight

import rego.v1

_pf_sfnenc_url := "https://docs.aws.amazon.com/step-functions/latest/apireference/API_EncryptionConfiguration.html"

_pf_sfnenc_fix := "Pair CUSTOMER_MANAGED_KMS_KEY with a KmsKeyId; leave KmsKeyId/KmsDataKeyReusePeriodSeconds out for AWS_OWNED_KEY"

_pf_sfnenc_res contains [name, enc, t] if {
	some rt in ["AWS::StepFunctions::StateMachine", "AWS::StepFunctions::Activity"]
	some name in resources_of_type(rt)
	props := input.resources[name].properties
	is_object(props)
	enc := object.get(props, "EncryptionConfiguration", null)
	is_object(enc)
	t := resolve(name, "Properties.EncryptionConfiguration.Type")
	is_string(t)
}

violation contains make_diag_full("pf-sfn-encryption-config", "ERROR", name,
	"Properties.EncryptionConfiguration",
	"EncryptionConfiguration.Type is CUSTOMER_MANAGED_KMS_KEY without a KmsKeyId; the create call fails with \"InvalidEncryptionConfiguration: Must set a valid kmsKeyId.\"",
	_pf_sfnenc_fix, _pf_sfnenc_url) if {
	some [name, enc, t] in _pf_sfnenc_res
	t == "CUSTOMER_MANAGED_KMS_KEY"
	not _pf_sfnlib_has(enc, "KmsKeyId")
}

violation contains make_diag_full("pf-sfn-encryption-config", "ERROR", name,
	sprintf("Properties.EncryptionConfiguration.%s", [f]),
	sprintf("EncryptionConfiguration.Type is AWS_OWNED_KEY but %s is set; the create call fails with \"InvalidEncryptionConfiguration: Custom %s is not allowed when selecting AWS_OWNED_KEY.\"", [f, lc]),
	_pf_sfnenc_fix, _pf_sfnenc_url) if {
	some [name, enc, t] in _pf_sfnenc_res
	t == "AWS_OWNED_KEY"
	some [f, lc] in _pf_sfnenc_owned
	_pf_sfnlib_has(enc, f)
}

_pf_sfnenc_owned contains ["KmsKeyId", "kmsKeyId"]

_pf_sfnenc_owned contains ["KmsDataKeyReusePeriodSeconds", "kmsDataKeyReusePeriodSeconds"]
