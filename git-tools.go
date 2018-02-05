package gitTools

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/google/go-github/github"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

const EncryptionTestFile = `AQIDAHifZNvRUqcIFKdQLDeOOv6YxQ2jxCBC7B4vz6iYJlQfSQFVFXpP+BHR+XxSct4L7pq8AAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMTWGv4ENjiDrfh+W4AgEQgDuapsQXggN0Ch1t17SHqy4CM+AzjFkMtTdbcmeBqEx9Vp1J4+LrRzWZNL8/ztIdx6XLKYipdEZRKxM/bgABAAEAAYlbXOWAdssF3x98NcQ9fnEAAQABAAEPinVr7LphOI68qbcoHcxxzKF0/yt2L97YBEeI8xhFJo08ic63SzrWVkWQUvkb7F1SmJzPKOFhyFi+B0/XcpMM`

var AwsKmsRegion string
var AwsKmsAccessKey string
var AwsKmsSecretKey string
var KmsKeyArn string
var requestTimeout = 10 * time.Second
var key string
var value string
var err error
var cmkID string
var ConfigPath string
var HomePath string
var AwsS3SecretKey string
var AwsS3AccessKey string
var AwsS3Bucket string
var AwsS3Region string
var NodeName string
var SerialNumber string
var PrivateIP string

// Model
type Package struct {
	FullName      string
	Description   string
	StarsCount    int
	ForksCount    int
	LastUpdatedBy string
}

func encryptionLicenseCheck() string {

	fmt.Println("Print KMS Key: ", KmsKeyArn)
	fmt.Println("Print KMS Secret: ", AwsKmsSecretKey)
	fmt.Println("Print KMS Access: ", AwsKmsAccessKey)
	fmt.Println("Print KMS Region: ", AwsKmsRegion)
	var resp string
	log.WithFields(log.Fields{"Network-Operator": "Encryption Manager"}).Info("Encryption Test == OK")
	encdata, iv, key := SplitEncFile([]byte(EncryptionTestFile))
	decryptkey := DecryptKey(key, "background")
	p := DecryptFile(encdata, iv, decryptkey)
	pass := fmt.Sprintf("%s", p)
	// fmt.Println("Print pass: ", pass)
	if strings.Contains(pass, "The brown fox jumpped over the moon for breakfast") {
		resp = "pass"
	} else {
		resp = "fail"
	}
	return resp
}

func decrypt(dataIn string) string {

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

	context := "background"
	fmt.Println("Print AWS Region: ", AwsKmsRegion)
	kmssvc = kms.New(session.New())

	filedata := []byte(dataIn)
	encdata, iv, key := SplitEncFile(filedata)
	decryptkey := DecryptKey(key, context)
	result := DecryptFile(encdata, iv, decryptkey)
	data := string(result)
	return data
}

func encrypt(dataIn string) string {

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

	context := "background"
	fmt.Println("Print AWS Region: ", AwsKmsRegion)

	kmssvc = kms.New(session.New())

	filedata := []byte(dataIn)
	cipherenvkey, plainenvkey := GenerateEnvKey(context)
	ciphertext, iv := EncryptFile(filedata, plainenvkey)
	result := CreateEncFile(ciphertext, iv, cipherenvkey)
	data := string(result)
	return data
}

// Kms encryption / decryption tools

var kmssvc *kms.KMS

//GenerateEnvKey This function is used to generate KMS encryption keys for
//envelope encryption
func GenerateEnvKey(context string) ([]byte, []byte) {
	//if viper.IsSet("AWS.Kms.KmsKey") {

	kmssvc = kms.New(session.New())

	genparams := &kms.GenerateDataKeyInput{
		KeyId: aws.String(KmsKeyArn),
		EncryptionContext: map[string]*string{
			"Application": aws.String(context),
		},
		KeySpec: aws.String("AES_256"),
	}
	resp, err := kmssvc.GenerateDataKey(genparams)
	if err != nil {
		AWSError(err)
	}
	plainkey := resp.Plaintext
	cipherkey := resp.CiphertextBlob
	return cipherkey, plainkey
}

//DecryptKey does the actual KMS decryption of the stored key
func DecryptKey(output []byte, context string) []byte {

	kmssvc = kms.New(session.New())

	keyparams := &kms.DecryptInput{
		CiphertextBlob: output, // Required
		EncryptionContext: map[string]*string{
			"Application": aws.String(context),
		},
	}

	plainkey, err := kmssvc.Decrypt(keyparams)
	if err != nil {
		AWSError(err)
	}
	decodelen := base64.StdEncoding.DecodedLen(len(plainkey.Plaintext))
	decodedplainkey := make([]byte, decodelen)
	base64.StdEncoding.Decode(decodedplainkey, plainkey.Plaintext)
	return plainkey.Plaintext
}

// BlockSize Export this value (which is always 16 lol) to other packages so they don't need
// to import crypto/aes
var BlockSize = aes.BlockSize

// DecryptFile This function uses the decrypted data encryption key and the
// retrieved IV to decrypt the data file
func DecryptFile(data []byte, iv []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		GenError(errors.New("DecryptFile - There was a cipher initialization error"))
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	return Unpad(data)
}

// EncryptFile This function uses the provided data encryption key and generates
// an IV to encrypt the data file
func EncryptFile(data []byte, key []byte) ([]byte, []byte) {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		GenError(errors.New("Encryptfile - There was an IV generation error"))
	}
	pmessage := Pad(data)
	ciphertext := make([]byte, len(pmessage))
	c, kerr := aes.NewCipher(key)
	if kerr != nil {
		GenError(errors.New("EncryptFile - There was a cipher initialization error"))
	}
	mode := cipher.NewCBCEncrypter(c, iv)
	mode.CryptBlocks(ciphertext, pmessage)
	return ciphertext, iv
}

// GenerateDataKey Does what's on the tin, generates the data encryption key
func GenerateDataKey() []byte {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		GenError(errors.New("GenerateDataKey - There was a key generation error"))
	}
	return key
}

//AWSError takes an AWS generated error and handles it
func AWSError(err error) {
	if awsErr, ok := err.(awserr.Error); ok {
		// Generic AWS error with Code, Message, and original error (if any)
		if origErr := awsErr.OrigErr(); origErr != nil {
			fmt.Printf("AWS Error: %s - %s %v\n", awsErr.Code(), awsErr.Message(), awsErr.OrigErr())
			os.Exit(1)
		} else {
			fmt.Printf("AWS Error: %s - %s \n", awsErr.Code(), awsErr.Message())
		}
		os.Exit(1)
		if reqErr, ok := err.(awserr.RequestFailure); ok {
			// A service error occurred
			fmt.Println(reqErr.Code(), reqErr.Message(), reqErr.StatusCode(), reqErr.RequestID())
			os.Exit(1)
		}
	} else {
		// This case should never be hit, the SDK should always return an
		// error which satisfies the awserr.Error interface.
		fmt.Println(err.Error())
		os.Exit(1)
	}
	return
}

//GenError takes other generated errors and handles them
func GenError(err error) {
	fmt.Printf("Error: %s", err.Error())
	os.Exit(1)
	return
}

var sep = []byte{0, 1, 0, 1, 0, 1}

//CreateEncFile takes the key, iv, and encrypted data and concatenates it to a file
func CreateEncFile(ciphertext []byte, iv []byte, cipherdatakey []byte) []byte {
	bufferslice := [][]byte{cipherdatakey, iv, ciphertext}
	concat := bytes.Join(bufferslice, sep)
	encodelen := base64.RawStdEncoding.EncodedLen(len(concat))
	encdata := make([]byte, encodelen)
	base64.RawStdEncoding.Encode(encdata, concat)
	return encdata
}

//SplitEncFile takes the concatenated file and splits out the key, iv, and data
func SplitEncFile(filedata []byte) ([]byte, []byte, []byte) {
	decodelen := base64.RawStdEncoding.DecodedLen(len(filedata))
	decodeddata := make([]byte, decodelen)
	base64.RawStdEncoding.Decode(decodeddata, filedata)
	returnslice := bytes.SplitN(decodeddata, sep, 3)
	key := returnslice[0]
	iv := returnslice[1]
	suffix := []byte{0}
	data := bytes.TrimSuffix(returnslice[2], suffix)
	return data, iv, key
}

//Unpad This function unpads pkcs#7 padding
func Unpad(in []byte) []byte {
	if len(in) == 0 {
		GenError(errors.New("Unpad - No data sent to unpad"))
	}

	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize {
		GenError(errors.New("Unpad - Padding larger than BlockSize or data"))
	} else if padding == 0 {
		GenError(errors.New("Unpad - Does not contain proper padding"))
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			GenError(errors.New("Unpad - Padded value larger than padding"))
		}
	}
	return in[:len(in)-int(padding)]
}

//Pad This function does pkcs#7 padding
func Pad(in []byte) []byte {
	padding := aes.BlockSize - (len(in) % aes.BlockSize)
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}
	return in
}

func listAWSKMSKeys() {

	svc := kms.New(session.New())
	input := &kms.ListKeysInput{}

	result, err := svc.ListKeys(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeDependencyTimeoutException:
				fmt.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeInternalException:
				fmt.Println(kms.ErrCodeInternalException, aerr.Error())
			case kms.ErrCodeInvalidMarkerException:
				fmt.Println(kms.ErrCodeInvalidMarkerException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

	fmt.Println(result)

}

func HostShell(commandString string) string {
	var stdoutBuf, stderrBuf bytes.Buffer

	cmd1 := "/bin/bash"
	args := []string{"-c", commandString}
	timeout := 10

	cmd := exec.Command(cmd1, args...)

	stdoutIn, _ := cmd.StdoutPipe()
	stderrIn, _ := cmd.StderrPipe()

	var errStdout, errStderr error
	stdout := io.MultiWriter(os.Stdout, &stdoutBuf)
	stderr := io.MultiWriter(os.Stderr, &stderrBuf)
	err := cmd.Start()
	if err != nil {
		log.Fatalf("cmd.Start() failed with '%s'\n", err)
		return ""
	}

	go func() {
		_, errStdout = io.Copy(stdout, stdoutIn)
		return
	}()

	go func() {
		_, errStderr = io.Copy(stderr, stderrIn)
		return
	}()

	// setup a buffer to capture standard output
	var buf bytes.Buffer
	defer buf.Reset()

	// create a channel to capture any errors from wait
	done := make(chan error)
	go func() {
		if _, err := buf.ReadFrom(stdoutIn); err != nil {
			panic("buf.Read(stdoutIn) error: " + err.Error())
			return
		}
		done <- cmd.Wait()
		return
	}()

	// block on select, and switch based on actions received
	select {
	case <-time.After(time.Duration(timeout) * time.Second):
		if err := cmd.Process.Kill(); err != nil {
			return "failed to kill: " + err.Error()
		}
		return "timeout reached, process killed"
	case err := <-done:
		if err != nil {
			close(done)
			return "process done, with error: " + err.Error()
		}
		return buf.String()
	}
	return ""

}

// Set visable to true for private repo
func GitCreateNewRepo(token string, name string, private bool) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	// list all repositories for the authenticated user
	repos, _, err := client.Repositories.List(ctx, "", nil)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	fmt.Println("Print repos: ", repos)
	// create a new private repository named "foo"
	repo := &github.Repository{
		Name:    github.String(name),
		Private: github.Bool(private),
	}
	client.Repositories.Create(ctx, "", repo)
}

func GitGetRepoInformation(token string, repoOwner string, repoName string) {

	context := context.Background()
	tokenService := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tokenClient := oauth2.NewClient(context, tokenService)

	client := github.NewClient(tokenClient)

	repo, _, err := client.Repositories.Get(context, repoOwner, repoName)

	if err != nil {
		fmt.Printf("Problem in getting repository information %v\n", err)
		os.Exit(1)
	}

	pack := &Package{
		FullName:    *repo.FullName,
		Description: *repo.Description,
		ForksCount:  *repo.ForksCount,
		StarsCount:  *repo.StargazersCount,
	}

	fmt.Printf("%+v\n", pack)
}

func GitGetRepoReadmeInfo(token string, repoOwner string, repoName string) {

	context := context.Background()
	tokenService := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tokenClient := oauth2.NewClient(context, tokenService)

	client := github.NewClient(tokenClient)

	// repository readme information
	readme, _, err := client.Repositories.GetReadme(context, repoOwner, repoName, nil)
	if err != nil {
		fmt.Printf("Problem in getting readme information %v\n", err)
		return
	}

	// get content
	content, err := readme.GetContent()
	if err != nil {
		fmt.Printf("Problem in getting readme content %v\n", err)
		return
	}

	fmt.Println(content)

}

func GitGetRepoLastCommitInfo(token string, repoOwner string, repoName string) {

	context := context.Background()
	tokenService := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tokenClient := oauth2.NewClient(context, tokenService)

	client := github.NewClient(tokenClient)

	commitInfo, _, err := client.Repositories.ListCommits(context, repoOwner, repoName, nil)

	if err != nil {
		fmt.Printf("Problem in commit information %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%+v\n", commitInfo[0]) // Last commit information

}

func GitGetFileContents(token string, repoOwner string, repoName string, fileName string) {

	context := context.Background()
	tokenService := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tokenClient := oauth2.NewClient(context, tokenService)

	client := github.NewClient(tokenClient)

	configFile, _, _, err := client.Repositories.GetContents(context, repoOwner, repoName, fileName, nil)

	if err != nil {
		fmt.Printf("Problem in commit information %v\n", err)
		os.Exit(1)
	}
	contents, _ := configFile.GetContent()

	fmt.Printf(contents) // Last commit information
}

func GitPutFileContents(token string, repoOwner string, repoName string, filePathName string) error {

	context := context.Background()
	tokenService := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tokenClient := oauth2.NewClient(context, tokenService)

	client := github.NewClient(tokenClient)
	owner := repoOwner
	repo := repoName
	//folders are created if they don't exist
	//if the file already exists the client will throw an exception
	path := filePathName

	contents := []byte("my file contents")
	message := "my commit"
	branch := "master"

	opts := github.RepositoryContentFileOptions{
		Message: &message,
		Content: contents,
		Branch:  &branch,
	}

	//returns meta-data of commit and wrapper obj of the github http repsonse
	_, _, err := client.Repositories.CreateFile(context, owner, repo, path, &opts)

	if err != nil {
		fmt.Println("Error!", err)
		return err
		os.Exit(1)
	}
	return nil
}

func GitPutEncryptedFileContents(token string, repoOwner string, repoName string, filePathName string, data string, updateMessage string) error {
	var encData string
	var contents []byte

	if viper.IsSet("Repository.Github.Encrypted") {
		encData = encrypt(data)
	}

	context := context.Background()
	tokenService := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tokenClient := oauth2.NewClient(context, tokenService)

	client := github.NewClient(tokenClient)
	owner := repoOwner
	repo := repoName
	//folders are created if they don't exist
	//if the file already exists the client will throw an exception
	path := filePathName

	if viper.IsSet("Repository.Github.Encrypted") {
		contents = []byte(encData)
	} else {
		contents = []byte(data)
	}

	message := updateMessage
	branch := "master"

	opts := github.RepositoryContentFileOptions{
		Message: &message,
		Content: contents,
		Branch:  &branch,
	}

	//returns meta-data of commit and wrapper obj of the github http repsonse
	_, _, err := client.Repositories.CreateFile(context, owner, repo, path, &opts)

	if err != nil {
		fmt.Println("Error!", err)
		return err
		os.Exit(1)
	}
	return nil
}

func GitUpdateEncryptedFileContents(token string, repoOwner string, repoName string, filePathName string, data string, updateMessage string) error {
	var encData string
	var contents []byte

	if viper.IsSet("Repository.Github.Encrypted") {
		encData = encrypt(data)
	}

	context := context.Background()
	tokenService := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tokenClient := oauth2.NewClient(context, tokenService)

	client := github.NewClient(tokenClient)
	owner := repoOwner
	repo := repoName
	//folders are created if they don't exist
	//if the file already exists the client will throw an exception
	path := filePathName

	if viper.IsSet("Repository.Github.Encrypted") {
		contents = []byte(encData)
	} else {
		contents = []byte(data)
	}
	message := updateMessage
	branch := "master"

	opts := github.RepositoryContentFileOptions{
		Message: &message,
		Content: contents,
		Branch:  &branch,
		SHA:     github.String(GitGetSha(client, repoOwner, repoName, filePathName)),
	}

	//returns meta-data of commit and wrapper obj of the github http repsonse
	_, _, err := client.Repositories.UpdateFile(context, owner, repo, path, &opts)

	if err != nil {
		fmt.Println("Error!", err)
		return err
		os.Exit(1)
	}
	return nil
}

func GitGetEncryptedFileContents(token string, repoOwner string, repoName string, fileName string) string {
	var encData string

	context := context.Background()
	tokenService := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tokenClient := oauth2.NewClient(context, tokenService)

	client := github.NewClient(tokenClient)

	configFile, _, _, err := client.Repositories.GetContents(context, repoOwner, repoName, fileName, nil)

	if err != nil {
		fmt.Printf("Problem in commit information %v\n", err)
		os.Exit(1)
	}
	contents, _ := configFile.GetContent()

	if viper.IsSet("Repository.Github.Encrypted") {
		encData = decrypt(contents)
		fmt.Println(encData) // Last commit information
		return encData
	}

	fmt.Println(contents) // Last commit information
	return contents
}

func GitExistEncryptedFile(token string, repoOwner string, repoName string, filePathName string) bool {

	context := context.Background()
	tokenService := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tokenClient := oauth2.NewClient(context, tokenService)

	client := github.NewClient(tokenClient)

	_, _, _, err := client.Repositories.GetContents(context, repoOwner, repoName, filePathName, nil)

	if err != nil {
		return false
	}
	return true
}

func GitGetSha(client *github.Client, repoOwner string, repoName string, filePathName string) string {
	opt := new(github.RepositoryContentGetOptions)
	context := context.Background()
	res, _, _, err := client.Repositories.GetContents(context, repoOwner, repoName, filePathName, opt)
	if err != nil {
		return ""
	}
	return *res.SHA
}
