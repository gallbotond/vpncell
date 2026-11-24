//go:build integration

package integration

// OpenVPN profiles are added with the OpenVPN backend (build step 5).

func setupOpenVPNLab() error       { return nil }
func setupOpenVPNVM() error        { return nil }
func openVPNLabSets() []profileSet { return nil }
func openVPNVMProfiles() []string  { return nil }
