// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "git-tools",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/vrctl.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	RootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {

	// Find home directory.
	home, err := homedir.Dir()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Search config in home directory with name ".git-tools" (without extension).
	viper.AddConfigPath(home)
	viper.SetConfigName("vrctl")

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	// Check for existing environment vars for KMS, if not set from viper config file

	KmsKeyArn = os.Getenv("AWS_KMS_KEY")
	if KmsKeyArn == "" {
		os.Setenv("AWS_KMS_KEY", viper.GetString("AWS.Kms.Key"))
		KmsKeyArn = os.Getenv("AWS_KMS_KEY")
	}

	AwsKmsRegion = os.Getenv("AWS_REGION")
	if AwsKmsRegion == "" {
		os.Setenv("AWS_REGION", viper.GetString("AWS.Kms.Region"))
		AwsKmsRegion = os.Getenv("AWS_REGION")

	}

	AwsKmsAccessKey = os.Getenv("AWS_ACCESS_KEY_ID")
	if AwsKmsAccessKey == "" {
		os.Setenv("AWS_ACCESS_KEY_ID", viper.GetString("AWS.Kms.AccessKey"))
		AwsKmsAccessKey = os.Getenv("AWS_ACCESS_KEY_ID")
	}

	AwsKmsSecretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	if AwsKmsSecretKey == "" {
		os.Setenv("AWS_SECRET_ACCESS_KEY", viper.GetString("AWS.Kms.SecretKey"))
		AwsKmsSecretKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	AwsS3Bucket = viper.GetString("AWS.Kms.Bucket")

}
