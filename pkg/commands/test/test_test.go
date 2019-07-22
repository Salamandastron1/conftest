package test

import (
	"testing"

	"github.com/spf13/viper"
)

func TestWarnQuerry(t *testing.T) {

	tests := []struct {
		in  string
		exp bool
	}{
		{"", false},
		{"warn", true},
		{"warnXYZ", false},
		{"warn_", false},
		{"warn_x", true},
		{"warn_x_y_z", true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			res := warnQ.MatchString(tt.in)

			if tt.exp != res {
				t.Fatalf("%s recognized as `warn` query - expected: %v actual: %v", tt.in, tt.exp, res)
			}
		})
	}
}

func TestCommandTest(t *testing.T) {
	testCommand := NewTestCommand()
	t.Run("Test command has all required flags", func(t *testing.T) {
		expectedFlags := []string{
			"fail-on-warn",
			"update",
			"combine-files",
		}
		for _, flag := range expectedFlags {
			if nil == testCommand.Flags().Lookup(flag) {
				t.Errorf("we are missing an expected flag: %s", flag)
			}
		}
	})
	t.Run("given a policy with rules and samples config files with populated objects", func(t *testing.T) {
		t.Run("when combine-files flag is true", func(t *testing.T) {
			combineFiles := true
			failOnWarn := true
			update := false
			policyFilePath := "testdata/policy"
			viper.Set("namespace", "main")
			t.Run("and there is a single, policy compliant, config file", func(t *testing.T) {
				err := RunTestCommand(
					combineFiles,
					failOnWarn,
					update,
					policyFilePath,
					[]string{"testdata/single_file_complete.tf"},
					testCommand,
				)
				if err != nil {
					t.Errorf("we should not have recieved an error: %v", err)
				}
			})

			t.Run("and there are multiple tf files, policy compliant, config file", func(t *testing.T) {
				t.Skip("this feature is not yet implemented")
				err := RunTestCommand(
					combineFiles,
					failOnWarn,
					update,
					policyFilePath,
					[]string{
						"testdata/multi_file_part_1.tf",
						"testdata/multi_file_part_2.tf",
					},
					testCommand,
				)
				if err != nil {
					t.Errorf("we should not have recieved an error: %v", err)
				}
			})
		})
	})

}

func TestFailQuery(t *testing.T) {

	tests := []struct {
		in  string
		exp bool
	}{
		{"", false},
		{"deny", true},
		{"denyXYZ", false},
		{"deny_", false},
		{"deny_x", true},
		{"deny_x_y_z", true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			res := denyQ.MatchString(tt.in)

			if tt.exp != res {
				t.Fatalf("%s recognized as `fail` query - expected: %v actual: %v", tt.in, tt.exp, res)
			}
		})
	}
}
