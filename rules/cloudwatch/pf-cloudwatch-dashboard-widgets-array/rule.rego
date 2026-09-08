package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-dashboard-widgets-array", "ERROR", name,
	"Properties.DashboardBody",
	"The widgets key is not an array; PutDashboard fails with \"Should be array\"",
	"Make widgets a JSON array of widget objects",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html") if {
	some name in resources_of_type("AWS::CloudWatch::Dashboard")
	body := resolve(name, "Properties.DashboardBody")
	is_string(body)
	json.is_valid(body)
	obj := json.unmarshal(body)
	is_object(obj)
	ws := object.get(obj, "widgets", "__pf_absent")
	ws != "__pf_absent"
	not is_array(ws)
}
