package test
 
import (
    "testing"
    "github.com/gruntwork-io/terratest/modules/terraform"
)
 
func TestAzureLinuxVMCreation(t *testing.T) {
    t.Parallel()
 
    terraformOptions := &terraform.Options{
        TerraformDir: "../", // Change this if Terraform code is in a different directory
    }
 
    // Run Terraform commands: Init & Apply
    terraform.InitAndApply(t, terraformOptions)
}
 