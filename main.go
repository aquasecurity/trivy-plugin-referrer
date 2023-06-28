package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/trivy/pkg/log"
)

type Insecure bool

func (i Insecure) NameOptions() []name.Option {
	return lo.Ternary(bool(i), []name.Option{name.Insecure}, nil)
}

func (i Insecure) RemoteOptions() []remote.Option {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: bool(i)}
	return []remote.Option{remote.WithTransport(tr)}
}

type putOptions struct {
	Insecure
	Annotations map[string]string
	Subject     string
}

type getOptions struct {
	Insecure
	Type      string
	Reference string
	Digest    string
}

type listOptions struct {
	Insecure
	Type              string
	Subject           string
	Format            string
	FilterAnnotations map[string]string
}

type treeOptions struct {
	Insecure
	Subject string
	Full    bool
}

func keyValueSliceToMap(s []string) (map[string]string, error) {
	m := make(map[string]string, len(s))
	for _, kv := range s {
		parts := strings.Split(kv, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid key-value pair: %s", kv)
		}
		m[parts[0]] = parts[1]
	}
	return m, nil
}

func main() {
	viper.SetEnvPrefix("trivy")
	viper.AutomaticEnv()

	rootCmd := &cobra.Command{
		Short: "A Trivy plugin for oci referrers",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			debug := viper.GetBool("debug")
			quiet := viper.GetBool("quiet")

			if err := log.InitLogger(debug, quiet); err != nil {
				return err
			}

			return nil
		},
	}
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "debug mode")
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "suppress log output")
	viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))
	rootCmd.PersistentFlags().Bool("insecure", false, "allow insecure server connections")
	viper.BindPFlag("insecure", rootCmd.PersistentFlags().Lookup("insecure"))

	putCmd := &cobra.Command{
		Use:   "put",
		Short: "put a referrer to the oci registry",
		Example: `  trivy image -q -f cyclonedx YOUR_IMAGE | trivy referrer put
  # Put SBOM attestation
  trivy referrer put -f sbom.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := viper.GetString("file")

			var reader io.Reader
			if path != "" {
				fp, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("error opening file: %w", err)
				}
				defer fp.Close()

				reader = fp
			} else {
				reader = os.Stdin
			}

			annList := viper.GetStringSlice("annotation")
			ann, err := keyValueSliceToMap(annList)
			if err != nil {
				return fmt.Errorf("error parsing annotations: %w", err)
			}

			err = putReferrer(reader, putOptions{
				Annotations: ann,
				Subject:     viper.GetString("subject"),
				Insecure:    Insecure(viper.GetBool("insecure")),
			})
			if err != nil {
				return fmt.Errorf("error putting referrer: %w", err)
			}

			return nil
		},
	}
	putCmd.Flags().StringP("file", "f", "", "file path. If a file path is not specified, it will accept input from the standard input.")
	viper.BindPFlag("file", putCmd.Flags().Lookup("file"))
	putCmd.Flags().StringSliceP("annotation", "", nil, "annotations associated with the artifact (can specify multiple or separate values with commas: key1=path1,key2=path2)")
	viper.BindPFlag("annotation", putCmd.Flags().Lookup("annotation"))
	putCmd.Flags().StringP("subject", "", "", "set the subject to a reference (If the value is not set, it will attempt to detect it automatically from the input)")
	viper.BindPFlag("subject", putCmd.Flags().Lookup("subject"))

	rootCmd.AddCommand(putCmd)

	getCmd := &cobra.Command{
		Use:   "get YOUR_IMAGE",
		Short: "get the referrer's artifact",
		Args:  cobra.ExactArgs(1),
		Example: `  $ trivy referrer get --type cyclonedx YOUR_IMAGE
  $ trivy referrer get --digest DIGEST YOUR_IMAGE`,
		RunE: func(cmd *cobra.Command, args []string) error {
			output := viper.GetString("output")
			var writer io.Writer
			if output == "" {
				writer = os.Stdout
			} else {
				fp, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("error creating file: %w", err)
				}
				defer fp.Close()

				writer = fp
			}

			t := viper.GetString("type")
			digest := viper.GetString("digest")

			err := getReferrer(writer, getOptions{
				Insecure:  Insecure(viper.GetBool("insecure")),
				Type:      t,
				Digest:    digest,
				Reference: args[0],
			})
			if err != nil {
				return fmt.Errorf("error getting referrer: %w", err)
			}

			return nil
		},
	}
	getCmd.Flags().StringP("type", "", "", "artifact type (cyclonedx, spdx-json, sarif, cosign-vuln)")
	viper.BindPFlag("type", putCmd.Flags().Lookup("type"))
	getCmd.Flags().StringP("digest", "", "", "referrer digest. If the length of the digest is only partial, search for artifacts with matching prefixes")
	viper.BindPFlag("digest", putCmd.Flags().Lookup("digest"))
	getCmd.Flags().StringP("output", "o", "", "output file name")
	viper.BindPFlag("output", putCmd.Flags().Lookup("output"))

	rootCmd.AddCommand(getCmd)

	listCmd := &cobra.Command{
		Use:     "list",
		Short:   "list referrers",
		Example: `  $ trivy referrer list YOUR_IMAGE`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			output := viper.GetString("output")
			var writer io.Writer
			if output == "" {
				writer = os.Stdout
			} else {
				fp, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("error creating file: %w", err)
				}
				defer fp.Close()

				writer = fp
			}

			t := viper.GetString("type")
			format := viper.GetString("format")
			annList := viper.GetStringSlice("filter-annotation")

			ann, err := keyValueSliceToMap(annList)
			if err != nil {
				return fmt.Errorf("invalid annotation: %w", err)
			}

			err = listReferrers(writer, listOptions{
				Insecure:          Insecure(viper.GetBool("insecure")),
				Type:              t,
				Subject:           args[0],
				Format:            format,
				FilterAnnotations: ann,
			})
			if err != nil {
				return fmt.Errorf("error getting referrer: %w", err)
			}

			return nil
		},
	}
	listCmd.Flags().StringSliceP("filter-annotation", "", nil, "filter annotations associated with the artifact (can specify multiple or separate values with commas: key1=path1,key2=path2)")
	viper.BindPFlag("filter-annotation", listCmd.Flags().Lookup("filter-annotation"))
	listCmd.Flags().StringP("format", "", "", "format (json, oneline, table)")
	viper.BindPFlag("format", listCmd.Flags().Lookup("format"))
	listCmd.Flags().StringP("type", "", "", "artifact type (cyclonedx, spdx-json, sarif, cosign-vuln)")
	viper.BindPFlag("type", listCmd.Flags().Lookup("type"))
	listCmd.Flags().StringP("output", "o", "", "output file name")
	viper.BindPFlag("output", listCmd.Flags().Lookup("output"))

	rootCmd.AddCommand(listCmd)

	treeCmd := &cobra.Command{
		Use:     "tree",
		Short:   "recurse into referrers and print the result as a tree",
		Example: `  $ trivy referrer tree YOUR_IMAGE`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			output := viper.GetString("output")
			var writer io.Writer
			if output == "" {
				writer = os.Stdout
			} else {
				fp, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("error creating file: %w", err)
				}
				defer fp.Close()

				writer = fp
			}
			full := viper.GetBool("full")

			err := treeReferrers(writer, treeOptions{
				Insecure: Insecure(viper.GetBool("insecure")),
				Subject:  args[0],
				Full:     full,
			})
			if err != nil {
				return fmt.Errorf("error getting referrer: %w", err)
			}

			return nil
		},
	}
	treeCmd.Flags().BoolP("full", "", false, "output the full digests")
	viper.BindPFlag("full", listCmd.Flags().Lookup("full"))
	treeCmd.Flags().StringP("output", "o", "", "output file name")
	viper.BindPFlag("output", listCmd.Flags().Lookup("output"))

	rootCmd.AddCommand(treeCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Logger.Fatal(err)
	}
}
