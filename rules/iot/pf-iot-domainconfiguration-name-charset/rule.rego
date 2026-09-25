package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-domainconfiguration-name-charset", "ERROR", name,
	"Properties.DomainConfigurationName",
	sprintf("DomainConfigurationName '%s' has characters outside [A-Za-z0-9_.-]; CreateDomainConfiguration answers \"Value at 'domainConfigurationName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w.-]+\"", [n]),
	"Use only letters, digits and _ . - in the domain configuration name",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_CreateDomainConfiguration.html") if {
	some name in resources_of_type("AWS::IoT::DomainConfiguration")
	n := _pf_iotlib_lit(name, "Properties.DomainConfigurationName")
	not regex.match(`^[A-Za-z0-9_.-]+$`, n)
}
