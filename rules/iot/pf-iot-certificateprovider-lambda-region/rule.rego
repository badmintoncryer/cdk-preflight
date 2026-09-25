package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-certificateprovider-lambda-region", "ERROR", name,
	"Properties.LambdaFunctionArn",
	sprintf("the certificate provider's Lambda is in '%s' but the provider deploys to '%s'; CreateCertificateProvider answers \"<arn> does not contain expected region, %s\"", [fnRegion, region, region]),
	"Point LambdaFunctionArn at a function in the certificate provider's own region",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_CreateCertificateProvider.html") if {
	some name in resources_of_type("AWS::IoT::CertificateProvider")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	fnRegion := _pf_iotlib_arn_region(resolve(name, "Properties.LambdaFunctionArn"), "lambda")
	fnRegion != region
}
