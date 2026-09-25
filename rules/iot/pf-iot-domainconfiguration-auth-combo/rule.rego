package cdk_preflight

import rego.v1

# Two ordered checks behind one combination table: the protocol has to be named
# whenever the authentication type is, and CUSTOM_AUTH additionally needs the
# authorizer to point at. AuthenticationType DEFAULT is left alone - it is the
# value that means "not configured", and nobody has measured that shape.
violation contains make_diag_full("pf-iot-domainconfiguration-auth-combo", "ERROR", name,
	"Properties.ApplicationProtocol",
	sprintf("the domain configuration sets AuthenticationType '%s' but no ApplicationProtocol; CreateDomainConfiguration answers \"The domain must configure a supported ApplicationProtocol when configuring an AuthenticationType.\"", [at]),
	"Add ApplicationProtocol (SECURE_MQTT, MQTT_WSS or HTTPS) alongside AuthenticationType",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_CreateDomainConfiguration.html") if {
	some name in resources_of_type("AWS::IoT::DomainConfiguration")
	at := _pf_iotlib_lit(name, "Properties.AuthenticationType")
	at != "DEFAULT"
	not _pf_iotlib_has(name, "ApplicationProtocol")
}

violation contains make_diag_full("pf-iot-domainconfiguration-auth-combo", "ERROR", name,
	"Properties.AuthorizerConfig",
	"the domain configuration uses CUSTOM_AUTH but sets no AuthorizerConfig; CreateDomainConfiguration answers \"The domain configuration must have a valid AuthorizerConfig configured when using CUSTOM_AUTH as the AuthenticationType.\"",
	"Add AuthorizerConfig.DefaultAuthorizerName naming an active custom authorizer",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_CreateDomainConfiguration.html") if {
	some name in resources_of_type("AWS::IoT::DomainConfiguration")
	_pf_iotlib_lit(name, "Properties.AuthenticationType") == "CUSTOM_AUTH"
	not _pf_iotlib_has(name, "AuthorizerConfig")
}
