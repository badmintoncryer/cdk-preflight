package cdk_preflight

import rego.v1

# Cross-resource: silent unless the security group, the subnet and both
# VPCs are all in this template.
violation contains make_diag_full("pf-eks-cluster-sg-and-subnets-same-vpc", "ERROR", name,
	"Properties.ResourcesVpcConfig.SecurityGroupIds",
	sprintf("security group %v is in VPC %v but the cluster's subnets are in VPC %v (\"Security group(s) are not (in/associated to) the same VPC as the subnets\")", [sg, sgvpc, snvpc]),
	"Create the cluster's security group in the same VPC as its subnets",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-resourcesvpcconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	some sgv in flatten_list(name, "Properties.ResourcesVpcConfig.SecurityGroupIds")
	sg := object.get(sgv.value, "__ref", "")
	sg in resources_of_type("AWS::EC2::SecurityGroup")
	sgvpc := resolve(sg, "Properties.VpcId")
	sgvpc in resources_of_type("AWS::EC2::VPC")
	some snv in flatten_list(name, "Properties.ResourcesVpcConfig.SubnetIds")
	sn := object.get(snv.value, "__ref", "")
	sn in resources_of_type("AWS::EC2::Subnet")
	snvpc := resolve(sn, "Properties.VpcId")
	snvpc in resources_of_type("AWS::EC2::VPC")
	sgvpc != snvpc
}
