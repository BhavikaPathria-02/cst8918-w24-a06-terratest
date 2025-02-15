// test_nic_connection.go
package test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestAzureNICConnection(t *testing.T) {
	terraformOptions := &terraform.Options{
		TerraformDir: "../",
	}

	terraform.InitAndApply(t, terraformOptions)

	// Fetch Terraform outputs
	nicName := terraform.Output(t, terraformOptions, "nic_name")
	resourceGroup := terraform.Output(t, terraformOptions, "resource_group_name")
	vmName := terraform.Output(t, terraformOptions, "vm_name")

	// Ensure NIC and VM names are not empty
	assert.NotEmpty(t, nicName, "NIC name should not be empty")
	assert.NotEmpty(t, resourceGroup, "Resource group should not be empty")
	assert.NotEmpty(t, vmName, "VM name should not be empty")
}
