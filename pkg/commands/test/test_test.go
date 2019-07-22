package test

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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

func Test_Multifile(t *testing.T) {
	t.Run("ProcessFile on mulitple files passed", func(t *testing.T) {

		t.Run("it should pass the --cross-ref flag as an arg", func(t *testing.T) {
			cmd := NewTestCommand()
			if cmd.Flags().Lookup("cross-ref") == nil {
				t.Errorf("Did not find `--cross-ref` in command flags. Flags looks like: %v", cmd.Flags())
			}
		})
		t.Run("function should fail if no args", func(t *testing.T) {
			cmd, _, _ := initBasic("../../../mockTestData/policy")
			args := []string{}

			if os.Getenv("BE_CRASHER") == "1" {
				TestFunction(cmd, args)
				return
			}

			sub := exec.Command(os.Args[0], "-test.run=Test_Multifile")
			sub.Env = append(os.Environ(), "BE_CRASHER=1")
			err := sub.Run()
			if e, ok := err.(*exec.ExitError); !ok || e.Success() {
				t.Fatalf("process ran with err %v, want exit status 1", err)
			}

		})
		t.Run("function should run if there is a arg", func(t *testing.T) {
			cmd, args, _ := initBasic("../../../mockTestData/policy")
			TestFunction(cmd, args)
		})
		t.Run("function run should if there are multiple args", func(t *testing.T) {
			cmd, args, _ := initBasic("../../../mockTestData/policy")
			args = append(args, "../../../mockTestData/weather.yaml")

			TestFunction(cmd, args)
		})
		//given an array of file paths, when the flag
		//exist it should combine the files into the
		//same namespace in a single object
		t.Run("given an array of file paths, it should concat all the files", func(t *testing.T) {
			args := []string{"../../../mockTestData/weather.yaml", "../../../mockTestData/name.yaml"}
			byteExpected, err := ioutil.ReadFile("../../../mockTestData/concatenated_Files.yaml")

			if err != nil {
				t.Errorf("Didn't expect file load to fail, error: %s", err)
			}
			expected := string(byteExpected)
			result, err := concatFiles(args)

			if err != nil {
				t.Errorf("Expected concatFiles to execute succesfully but instead got:\n%s", err)
			}

			if result != expected {
				t.Errorf("file outputs not the same. Expected:\n%v\n\n but got:\n%s", expected, result)
			}
		})

		t.Run("given an array of file paths with varying line endings, it should concat all the files consistently", func(t *testing.T) {
			args := []string{"../../../mockTestData/weather.yaml", "../../../mockTestData/name-newline.yaml"}
			viper.Set("cross-ref", true)
			byteExpected, err := ioutil.ReadFile("../../../mockTestData/concatenated_Files.yaml")

			if err != nil {
				t.Errorf("Didn't expect file load to fail, error: %s", err)
			}

			expected := string(byteExpected)
			result, err := concatFiles(args)

			if err != nil {
				t.Errorf("Expected concatFiles to execute succesfully but instead got:\n%s", err)
			}

			if result != expected {
				t.Errorf("file outputs not the same. Expected:\n%b\n\n but got:\n%b", byteExpected, []byte(result))
			}
		})

		t.Run("given a concatted file, the rego tests run and warn", func(t *testing.T) {
			viper.Set("cross-ref", true)
			policy := "../../../mockTestData/policy_with_rules"
			extraArgs := []string{"../../../mockTestData/weather.yaml", "../../../mockTestData/name.yaml"}
			expected := "Found name 'service' and weather 'bad'"
			result := executeTestFunction(policy, extraArgs)

			if !strings.Contains(result, expected) {
				t.Errorf("Expecting Rego to output `%s`; instead got `%s`", expected, result)
			}
		})

		// t.Run("given a concatted file with two same keys, the rego tests run", func(t *testing.T) {
		// viper.Set("cross-ref", true)
		// policy := "../../../mockTestData/policy_same_keys"
		// extraArgs := []string{"../../../mockTestData/weather.yaml", "../../../mockTestData/weather-good.yaml"}
		// expected := "I don't like bad weather"
		// result := executeTestFunction(policy, extraArgs)
		// // #			if !strings.Contains(result, expected) {
		// t.Errorf("Expecting Rego to output `%s`; instead got `%s`", expected, result)
		// }
		// })

		t.Run("given a concatted yaml file, do we properly handle multiple '---' in the file?", func(t *testing.T) {
			viper.Set("cross-ref", true)
			policy := "../../../mockTestData/policy_with_rules"
			extraArgs := []string{"../../../mockTestData/weather-multi-file.yaml"}
			expected := "Found name 'service' and weather 'bad'"
			result := executeTestFunction(policy, extraArgs)

			if !strings.Contains(result, expected) {
				t.Errorf("Expecting Rego to output `%s`; instead got `%s`", expected, result)
			}
		})
	})
}

func initBasic(policy string) (*cobra.Command, []string, context.Context) {
	cmd := &cobra.Command{}
	viper.Set("policy", policy)
	viper.Set("no-color", true)
	viper.Set("namespace", "main")

	ctx := context.Background()

	args := []string{"../../../mockTestData/name.yaml"}

	return cmd, args, ctx
}

func executeTestFunction(policy string, extraArgs []string) string {
	cmd, _, _ := initBasic(policy)

	//	args = append(args, extraArgs...)
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	TestFunction(cmd, extraArgs)

	w.Close()
	os.Stdout = old
	result := <-outC
	return result
}
