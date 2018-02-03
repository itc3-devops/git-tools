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
	"strconv"

	"github.com/spf13/cobra"
)

// utilCmd represents the util command
var utilCmd = &cobra.Command{
	Use:   "util",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(os.Args) > 4 && os.Args[2] == "readme" {
			f1 := os.Args[3]
			f2 := os.Args[4]
			GitGetRepoReadmeInfo(f1, f2)
		} else if len(os.Args) > 4 && os.Args[2] == "info" {
			f1 := os.Args[3]
			f2 := os.Args[4]
			GitGetRepoInformation(f1, f2)
		} else if len(os.Args) > 4 && os.Args[2] == "create" {
			f1 := os.Args[3]
			f2, _ := strconv.ParseBool(os.Args[4])
			GitCreateNewRepo(f1, f2)
		} else if len(os.Args) > 5 && os.Args[2] == "read" {
			f1 := os.Args[3]
			f2 := os.Args[4]
			f3 := os.Args[5]
			GitGetEncryptedFileContents(f1, f2, f3)
		} else if len(os.Args) > 7 && os.Args[2] == "write" {
			f1 := os.Args[3]
			f2 := os.Args[4]
			f3 := os.Args[5]
			f4 := os.Args[6]
			f5 := os.Args[7]
			exist := GitExistEncryptedFile(f1, f2, f3)
			if exist == true {
				fmt.Println("File already exist, updating....")
				GitUpdateEncryptedFileContents(f1, f2, f3, f4, f5)
			} else {
				fmt.Println("File does not exist, creating....")
				GitPutEncryptedFileContents(f1, f2, f3, f4, f5)
			}

		}
	},
}

func init() {
	RootCmd.AddCommand(utilCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// utilCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// utilCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
