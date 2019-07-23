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

	"github.com/containerd/containerd/log"
	"github.com/open-policy-agent/opa/ast"
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
			t.Skip()
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
			t.Skip()
			cmd := NewTestCommand()
			if cmd.Flags().Lookup("cross-ref") == nil {
				t.Errorf("Did not find `--cross-ref` in command flags. Flags looks like: %v", cmd.Flags())
			}
		})
		t.Run("function should fail if no args", func(t *testing.T) {
			t.Skip()
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
			t.Skip()
			cmd, args, _ := initBasic("../../../mockTestData/policy")
			TestFunction(cmd, args)
		})
		t.Run("function run should if there are multiple args", func(t *testing.T) {
			t.Skip()
			cmd, args, _ := initBasic("../../../mockTestData/policy")
			args = append(args, "../../../mockTestData/weather.yaml")

			TestFunction(cmd, args)
		})
		t.Run("given an array of file paths, it should concat all the files", func(t *testing.T) {
			t.Skip()
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
			t.Skip()
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
			t.Skip()
			viper.Set("cross-ref", true)
			policy := "../../../mockTestData/policy_with_rules"
			extraArgs := []string{"../../../mockTestData/weather.yaml", "../../../mockTestData/name.yaml"}
			expected := "Found name 'service' and weather 'bad'"
			result := executeTestFunction(policy, extraArgs)

			if !strings.Contains(result, expected) {
				t.Errorf("Expecting Rego to output `%s`; instead got `%s`", expected, result)
			}
		})
		t.Run("Multi-file support", func(t *testing.T) {

			testCommand := NewTestCommand()
			t.Run("Test command has all required flags", func(t *testing.T) {
				t.Skip()
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
				t.Skip()
				t.Run("when combine-files flag is true", func(t *testing.T) {

					t.Run("and there is a single, policy compliant, config file", func(t *testing.T) {
						_, ctx, compiler := initMulti("../../../mockTestData/tfPolicy")
						expected := false
						files := []string{"../../../mockTestData/single_file_complete.tf"}
						result := loopOverFiles(ctx, files, compiler)
						if result != expected {
							t.Errorf("expected %v but got %v", expected, result)
						}
					})
				})
			})
			t.Run("and there are multiple tf files, policy compliant, config file", func(t *testing.T) {
				_, ctx, compiler := initMulti("../../../mockTestData/tfPolicy")
				files := []string{
					"../../../mockTestData/multi_file_part_1.tf",
					"../../../mockTestData/multi_file_part_2.tf",
				}
				expected := false
				result := loopOverFiles(ctx, files, compiler)

				if result != expected {
					t.Errorf("expected %v but got %v", expected, result)
				}
			})
		})
		t.Run("given a concatted yaml file, do we properly handle multiple '---' in the file?", func(t *testing.T) {
			t.Skip()
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

func initMulti(policy string) (*cobra.Command, context.Context, *ast.Compiler) {
	cmd := &cobra.Command{}
	viper.Set("policy", policy)
	viper.Set("no-color", true)
	viper.Set("namespace", "main")
	compiler, err := buildCompiler(policy)
	ctx := context.Background()

	if err != nil {
		log.G(ctx).Fatalf("Invalid Policy %s", err)
	}

	return cmd, ctx, compiler
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
