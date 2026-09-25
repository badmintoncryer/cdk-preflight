package cdk_preflight

import rego.v1

# The CloudFormation handler (not the service API) decides which properties may
# travel together: it defaults CertificateMode to DEFAULT and then picks one of
# three registration calls - RegisterCertificateWithoutCA, CreateCertificateFromCsr
# or RegisterCertificate - and rejects the request when the properties match
# none of them. That happens before any call, so the PEMs are never read.
violation contains make_diag_full("pf-iot-certificate-mode-combo", "ERROR", name,
	"Properties.CertificateMode",
	sprintf("CertificateMode '%s' with %s is not one of the shapes the CloudFormation handler registers; it answers \"For certificate mode Default, one of the following combinations must be specified exactly: [CertificatePem and CACertificatePem] OR [CertificateSigningRequest]\" (or, for SNI_ONLY, \"the following combination must be specified exactly: [CertificatePem]\")", [mode, _pf_iotcmc_desc(shape)]),
	"Register the certificate with one of the three accepted property sets",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-certificate.html") if {
	some name in resources_of_type("AWS::IoT::Certificate")
	mode := object.get(_pf_iotlib_props(name), "CertificateMode", "DEFAULT")
	mode in {"DEFAULT", "SNI_ONLY"}
	shape := {k |
		some k in ["CertificatePem", "CACertificatePem", "CertificateSigningRequest"]
		_pf_iotlib_has(name, k)
	}
	not _pf_iotcmc_ok(mode, shape)
}

_pf_iotcmc_ok(mode, shape) if {
	mode == "SNI_ONLY"
	shape == {"CertificatePem"}
}

_pf_iotcmc_ok(mode, shape) if {
	mode == "DEFAULT"
	shape == {"CertificateSigningRequest"}
}

_pf_iotcmc_ok(mode, shape) if {
	mode == "DEFAULT"
	shape == {"CertificatePem", "CACertificatePem"}
}

_pf_iotcmc_desc(shape) := "no certificate property at all" if {
	count(shape) == 0
}

_pf_iotcmc_desc(shape) := concat(" + ", sort(shape)) if {
	count(shape) > 0
}
