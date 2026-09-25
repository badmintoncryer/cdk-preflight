package cdk_preflight

import rego.v1

# The enum still lists CREDENTIAL_PROVIDER and JOBS - the account's own
# iot:Jobs and iot:CredentialProvider endpoints are AWS-managed and predate the
# restriction - but CreateDomainConfiguration takes DATA and nothing else.
violation contains make_diag_full("pf-iot-domainconfiguration-service-type", "ERROR", name,
	"Properties.ServiceType",
	sprintf("ServiceType '%s' cannot be created; CreateDomainConfiguration answers \"CreateDomainConfiguration only supports DATA Service Type\" (and \"Invalid Service Type\" for JOBS)", [st]),
	"Use ServiceType DATA, or drop the property and take the default",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_CreateDomainConfiguration.html") if {
	some name in resources_of_type("AWS::IoT::DomainConfiguration")
	st := _pf_iotlib_lit(name, "Properties.ServiceType")
	st != "DATA"
}
