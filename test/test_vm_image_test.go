package test

import (
	"testing"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/gruntwork-io/terratest/modules/ssh"
	"github.com/stretchr/testify/assert"
)

func TestAzureVMUbuntuVersion(t *testing.T) {
	t.Parallel()

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
	}

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	// Get VM Public IP from Terraform output
	publicIP := terraform.Output(t, terraformOptions, "public_ip")

	// Generate an SSH key pair
	keyPair := ssh.KeyPair{
		PrivateKey: "~/.ssh/id_rsa",
		PublicKey:  "~/.ssh/id_rsa.pub",
	}

	// Define SSH host connection
	sshHost := ssh.Host{
		Hostname:    publicIP,
		SshUserName: "azureadmin",
		SshKeyPair:  &keyPair,
	}

	// Run the command to check Ubuntu version
	ubuntuVersion, err := ssh.CheckSshCommandE(t, sshHost, "lsb_release -d | awk -F':' '{print $2}'")
	assert.NoError(t, err, "Failed to execute SSH command")
	assert.Contains(t, ubuntuVersion, "Ubuntu 22.04", "Expected Ubuntu 22.04 LTS")
}
