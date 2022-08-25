package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/briandowns/spinner"
	"github.com/cli/go-gh"
	"github.com/cli/go-gh/pkg/api"
	"github.com/fatih/color"
	vault "github.com/hashicorp/vault/api"
	"github.com/pterm/pterm"
	"github.com/shurcooL/graphql"
	"github.com/spf13/cobra"
)

var (

	// Set up main variables
	noCache             = false
	confirm             = false
	srcHostname         string
	dstHostname         string
	srcOrganization     string
	dstOrganization     string
	srcToken            string
	dstToken            string
	vaultMountpoint     string
	vaultValueKey       string
	vaultPathKeys       []string
	vaultToken          string
	vaultKvv1           = false
	logFile             *os.File
	reposFile           *os.File
	reposFilePath       string
	reposFromFile       bool
	maxReadThreads      int
	maxWriteThreads     int
	repositories        []Repository = []Repository{}
	webhooks            []Webhook    = []Webhook{}
	webhookResultsTable pterm.TableData
	waitGroup           sync.WaitGroup
	missingSecrets      int = 0
	patchFailed         int = 0
	patchSucceeded      int = 0

	// Create some colors and a spinner
	red  = color.New(color.FgRed).SprintFunc()
	cyan = color.New(color.FgCyan).SprintFunc()
	sp   = spinner.New(spinner.CharSets[2], 100*time.Millisecond)

	// set up clients
	srcRestClient api.RESTClient
	dstRestClient api.RESTClient
	graphqlClient api.GQLClient

	// Create the root cobra command
	rootCmd = &cobra.Command{
		Use:           "gh migrate-webhook-secrets",
		Short:         "GitHub CLI extension to migrate webhook secrets",
		Long:          `GitHub CLI extension to migrate webhook secrets. Supports HashiCorp Vault (KV V1 & V2) as the secret storage intermediary.`,
		Version:       "0.2.1",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          CloneWebhooks,
	}

	// set up graphql query for repos
	orgRepositoriesQuery struct {
		Organization struct {
			Repositories Repos `graphql:"repositories(first: 100, after: $page, orderBy: {field: NAME, direction: ASC})"`
		} `graphql:"organization(login: $owner)"`
	}
)

type User struct {
	Login string
}
type RateResponse struct {
	Limit     int
	Remaining int
	Reset     int
	Used      int
}
type ApiResponse struct {
	Resources struct {
		Core    RateResponse
		Graphql RateResponse
	}
	Message string
	Rate    RateResponse
}
type Organization struct {
	Login string
}
type Repos struct {
	PageInfo struct {
		HasNextPage bool
		EndCursor   graphql.String
	}
	Nodes []Repository
}
type Repository struct {
	Name          string
	NameWithOwner string
	Owner         Organization
	Description   string
	URL           string
}
type WebHookConfig struct {
	URL          string `json:"url"`
	Content_Type string `json:"content_type"`
	Insecure_SSL string `json:"insecure_ssl"`
	Secret       string `json:"secret"`
	Token        string
	Digest       string
}
type Webhook struct {
	ID            int
	Repository    string
	Name          string        `json:"name"`
	Config        WebHookConfig `json:"config"`
	Events        []string      `json:"events"`
	Active        bool          `json:"active"`
	Exists        bool
	DstRepoExists bool
	Skip          bool
}
type WebHookPatch struct {
	URL          string `json:"url"`
	Content_Type string `json:"content_type"`
	Insecure_SSL string `json:"insecure_ssl"`
	Secret       string `json:"secret"`
}
type VaultAppRoleLogin struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}

func init() {

	// base flags
	rootCmd.PersistentFlags().StringVar(
		&srcHostname,
		"source-hostname",
		"github.com",
		"Set source GitHub hostname",
	)
	rootCmd.PersistentFlags().StringVar(
		&dstHostname,
		"destination-hostname",
		"github.com",
		"Set destination GitHub hostname",
	)
	rootCmd.PersistentFlags().StringVar(
		&srcOrganization,
		"source-org",
		"",
		"Set source organization to migrate from",
	)
	rootCmd.PersistentFlags().StringVar(
		&dstOrganization,
		"destination-org",
		"",
		"Set destination organization to migrate to",
	)
	rootCmd.PersistentFlags().StringVar(
		&srcToken,
		"source-token",
		"",
		"Optional token for authentication (uses GitHub CLI built-in authentication)",
	)
	rootCmd.PersistentFlags().StringVar(
		&dstToken,
		"destination-token",
		"",
		"Optional token for authentication (uses GitHub CLI built-in authentication)",
	)
	rootCmd.PersistentFlags().IntVar(
		&maxReadThreads,
		"read-threads",
		5,
		"Number of threads to process at a time.",
	)
	rootCmd.PersistentFlags().IntVar(
		&maxWriteThreads,
		"write-threads",
		1,
		"Number of write threads to process at a time. (WARNING: increasing beyond 1 can trigger the secondary rate limit.)",
	)

	// vault flags
	rootCmd.PersistentFlags().StringVar(
		&vaultMountpoint,
		"vault-mountpoint",
		"secret",
		"The mount point of the secrets on the Vault server",
	)
	rootCmd.PersistentFlags().StringSliceVar(
		&vaultPathKeys,
		"vault-path-keys",
		[]string{},
		"The key in the webhook URL (ex: <webhook-server>?secret=<vault-path-key>) to use for finding the corresponding secret",
	)
	rootCmd.PersistentFlags().StringVar(
		&vaultValueKey,
		"vault-value-key",
		"value",
		"The key in the Vault secret corresponding to the webhook secret value",
	)
	rootCmd.PersistentFlags().BoolVar(
		&vaultKvv1,
		"vault-kvv1",
		false,
		"Use Vault KVv1 instead of KVv2",
	)

	// boolean switches
	rootCmd.PersistentFlags().BoolVar(
		&noCache,
		"no-cache",
		false,
		"Disable cache for GitHub API requests",
	)
	rootCmd.PersistentFlags().BoolVar(
		&confirm,
		"confirm",
		false,
		"Auto respond to confirmation prompt",
	)

	rootCmd.Args = cobra.MaximumNArgs(1)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		ExitOnError(err)
	}
}

func ExitOnError(err error) {
	if err != nil {
		rootCmd.PrintErrln(red(err.Error()))
		os.Exit(1)
	}
}

func OutputFlags(key string, value string) {
	sep := ": "
	fmt.Println(fmt.Sprint(cyan(key), sep, value))
	Log(fmt.Sprint(key, sep, value))
}

func OutputNotice(message string) {
	Output(message, "default", false, false)
}

func OutputError(message string, exit bool) {
	sp.Stop()
	Output(message, "red", true, exit)
}

func Output(message string, color string, isErr bool, exit bool) {

	if isErr {
		message = fmt.Sprint("[ERROR] ", message)
	}
	Log(message)

	switch {
	case color == "red":
		message = red(message)
	}
	fmt.Println(message)
	if exit {
		fmt.Println("")
		os.Exit(1)
	}
}

func DebugAndStatus(message string) string {
	sp.Suffix = fmt.Sprint(
		" ",
		message,
	)
	return Debug(message)
}

func Debug(message string) string {
	Log(message)
	return message
}

func Log(message string) {
	if message != "" {
		message = fmt.Sprint(
			"[",
			time.Now().Format("2006-01-02 15:04:05"),
			"] ",
			message,
		)
	}
	_, err := logFile.WriteString(
		fmt.Sprintln(message),
	)
	if err != nil {
		fmt.Println(red("Unable to write to log file."))
		fmt.Println(red(err))
		os.Exit(1)
	}
}

func LF() {
	Output("", "default", false, false)
}

func LogLF() {
	Log("")
}

func Truncate(str string, limit int) string {
	lastSpaceIx := -1
	len := 0
	for i, r := range str {
		if unicode.IsSpace(r) {
			lastSpaceIx = i
		}
		len++
		if len >= limit {
			if lastSpaceIx != -1 {
				return fmt.Sprint(str[:lastSpaceIx], "...")
			} else {
				return fmt.Sprint(str[:limit], "...")
			}
		}
	}
	return str
}

func GetReaderFromObject(thisStruct interface{}) *bytes.Reader {
	// convert the struct to io.reader
	data, err := json.Marshal(&thisStruct)
	if err != nil {
		sp.Stop()
		OutputError(err.Error(), true)
	}
	return bytes.NewReader(data)
}

func AskForConfirmation(s string) (res bool, err error) {
	// read the input
	reader := bufio.NewReader(os.Stdin)
	// loop until a response is valid
	for {
		fmt.Printf("%s [y/n]: ", s)
		response, err := reader.ReadString('\n')
		Debug(fmt.Sprint("User responded with: ", response))
		if err != nil {
			return false, err
		}
		response = strings.ToLower(strings.TrimSpace(response))
		if response == "y" || response == "yes" {
			return true, err
		} else if response == "n" || response == "no" {
			return false, err
		}
	}
}

func GetOpts(hostname, token string) (options api.ClientOptions) {
	// set options
	opts := api.ClientOptions{
		Host:        hostname,
		EnableCache: !noCache,
		CacheTTL:    time.Hour,
	}
	if token != "" {
		opts.AuthToken = token
	}
	return opts
}

func ValidateApiRate(client api.RESTClient, requestType string) (err error) {
	apiResponse := ApiResponse{}
	attempts := 0

	for {

		// after 240 attempts (1 hour), end the scrip.
		if attempts >= 240 {
			return errors.New(
				fmt.Sprint(
					"After an hour of retrying, the API rate limit has not ",
					"refreshed. Aborting.",
				),
			)
		}

		// get the current rate liit left or error out if request fails
		err = client.Get("rate_limit", &apiResponse)
		if err != nil {
			Debug("Failed to get rate limit from GitHub server.")
			return err
		}

		// if rate limiting is disabled, do not proceed
		if apiResponse.Message == "Rate limiting is not enabled." {
			Debug("Rate limit is not enabled.")
			return err
		}
		// choose which response to validate
		rateRemaining := 0
		switch {
		default:
			return errors.New(
				fmt.Sprintf(
					"Invalid API request type provided: '%s'",
					requestType,
				),
			)
		case requestType == "core":
			rateRemaining = apiResponse.Resources.Core.Remaining
		case requestType == "graphql":
			rateRemaining = apiResponse.Resources.Graphql.Remaining
		}
		// validate there is rate left
		if rateRemaining <= 0 {
			attempts++
			DebugAndStatus(
				fmt.Sprintf(
					fmt.Sprintf(
						"API rate limit (%s) has none remaining. Sleeping for 15 seconds (attempt #%d)",
						requestType,
						attempts,
					),
				),
			)
			time.Sleep(15 * time.Second)
		} else {
			break
		}
	}
	return err
}

func AuthUser(vaultClient *vault.Client, roleId string, secretId string) (string, error) {
	// step: create the token request
	request := vaultClient.NewRequest("POST", "/v1/auth/approle/login")
	login := VaultAppRoleLogin{
		SecretID: secretId,
		RoleID:   roleId,
	}
	if err := request.SetJSONBody(login); err != nil {
		return "", err
	}

	// step: make the request
	resp, err := vaultClient.RawRequest(request)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	// step: parse and return auth
	secret, err := vault.ParseSecret(resp.Body)
	if err != nil {
		return "", err
	}

	return secret.Auth.ClientToken, err
}

func GetVaultToken(client *vault.Client) (token string, err error) {

	DebugAndStatus("Determining Vault authentication method...")

	// Get security credentials from environment
	vaultToken = os.Getenv("VAULT_TOKEN")
	vaultRoleId := os.Getenv("VAULT_ROLE_ID")
	vaultSecretId := os.Getenv("VAULT_SECRET_ID")

	// determine if we should auth with role id and secret id
	if vaultRoleId != "" && vaultSecretId != "" {
		Debug("Role ID and Secret ID provided. Authenticating and looking up token...")
		vaultToken, err = AuthUser(client, vaultRoleId, vaultSecretId)
		if err != nil {
			return "", err
		}
	} else if vaultToken != "" {
		Debug("Vault token manually provided.")
	}

	// validate a token exists
	if vaultToken == "" {
		err = errors.New(
			fmt.Sprint(
				"No valid authentication was provided. Either 'VAULT_TOKEN' ",
				"or  'VAULT_ROLE_ID' & 'VAULT_SECRET_ID' must be defined.",
			),
		)
	}
	return vaultToken, err
}

func GetVaultClient() (client *vault.Client, err error) {

	// get Vault server address
	vaultServer := os.Getenv("VAULT_ADDR")

	// skip this step if VAULT_ADDR isn't provided
	if vaultServer == "" {
		return nil, err
	}

	// set up vault
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = vaultServer
	client, err = vault.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}
	return client, err
}

func GetVaultSecret(key string) (secret string, connErr error, pathErr error) {

	// Get the Vault client. If no vault client and no errors were returned,
	// skip this step
	vaultClient, connErr := GetVaultClient()
	if vaultClient == nil && connErr == nil {
		return "", connErr, pathErr
	}

	// get the token if one isn't already provided
	if vaultToken == "" {
		vaultToken, connErr = GetVaultToken(vaultClient)
		if connErr != nil {
			return "", connErr, pathErr
		}
	}

	// authenticate
	vaultClient.SetToken(vaultToken)

	var secretValue = ""
	var secretInterface interface{}
	var foundKey bool = false

	if vaultKvv1 {
		// query using kvv1
		kvv1Response, pathErr := vaultClient.KVv1(vaultMountpoint).Get(context.Background(), key)
		if pathErr != nil {
			return "", connErr, pathErr
		}
		secretInterface, foundKey = kvv1Response.Data[vaultValueKey]

	} else {
		// query using kvv2
		kvv2Response, pathErr := vaultClient.KVv2(vaultMountpoint).Get(context.Background(), key)
		if pathErr != nil {
			return "", connErr, pathErr
		}
		secretInterface, foundKey = kvv2Response.Data[vaultValueKey]
	}

	// validate the interface contains the matching key.
	if foundKey {
		secretValue = secretInterface.(string)
	} else {
		pathErr = errors.New(
			fmt.Sprintf(
				"Key '%s' not found in secret.",
				vaultValueKey,
			),
		)
	}
	return secretValue, connErr, pathErr
}

func LookupWebhooks(repository Repository) {

	// set a var to store the webhook array in
	srcWebhooksResponse := []Webhook{}
	dstWebhooksResponse := []Webhook{}

	// print out current repository information
	Debug(
		fmt.Sprintf(
			"Fetching webhooks for repository '%s'...",
			repository.Name,
		),
	)

	// validate we have API attempts left
	timeoutErr := ValidateApiRate(srcRestClient, "core")
	if timeoutErr != nil {
		OutputError(timeoutErr.Error(), true)
	}

	// query for the webhooks on this repository
	// this also validates the source repository
	srcLookupErr := srcRestClient.Get(
		fmt.Sprintf(
			"repos/%s/%s/hooks",
			srcOrganization,
			repository.Name,
		),
		&srcWebhooksResponse,
	)

	// Non-200 errors should fail out
	if srcLookupErr != nil {
		OutputError(srcLookupErr.Error(), true)
	}

	// log when no results are found (success, but no hooks)
	if len(srcWebhooksResponse) == 0 {
		Debug(
			fmt.Sprintf(
				"No webhooks found for repository '%s'.",
				repository.Name,
			),
		)
	} else {
		Debug(
			fmt.Sprintf(
				"Found %d webhooks for repository '%s'.",
				len(srcWebhooksResponse),
				repository.Name,
			),
		)
	}

	// validate we have API attempts left on destination
	timeoutErr = ValidateApiRate(dstRestClient, "core")
	if timeoutErr != nil {
		OutputError(timeoutErr.Error(), true)
	}

	// query for webhooks on the destination
	err := dstRestClient.Get(
		fmt.Sprintf(
			"repos/%s/%s/hooks",
			dstOrganization,
			repository.Name,
		),
		&dstWebhooksResponse,
	)
	// Non-200 errors should fail out
	dstRepoExists := true
	if err != nil {
		dstRepoExists = false
		Log(fmt.Sprint("[WARNING] Could not find destination repo. Will skip webhooks. Error: ", err.Error()))
	}

	// add the webhooks to the table data for visibility
	for i, webhook := range srcWebhooksResponse {
		// update properties on the webhook
		webhook.Repository = repository.Name
		webhook.DstRepoExists = dstRepoExists
		webhook.Exists = false
		webhook.Config.Secret = "" // always clear this out as it contains the tokenized version (ex: ********)
		webhook.Skip = true

		// set variables for looking up secrets
		webhookLookupSecret := true
		webhookSecretPath := repository.Name

		// set display variables
		webhookName := repository.Name
		webhookId := strconv.Itoa(webhook.ID)
		webhookUrl := webhook.Config.URL

		// only needs this var for secret lookup stuff
		webhookSecretFound := "Unknown"
		webhookAction := "Unknown"

		if !dstRepoExists {
			webhookLookupSecret = false
			webhookSecretFound = "Skipped"
			webhookAction = "Skip: No Destination Repo"
		}

		// if the destination has webhooks, see if there's a match already
		if len(dstWebhooksResponse) > 0 && dstRepoExists {

			Debug(
				fmt.Sprintf(
					"Looking up webhook URL %s from repository %s in destination webhooks...",
					webhook.Config.URL,
					webhook.Repository,
				),
			)

			// loop through all destination webhooks
			for _, dstWebhook := range dstWebhooksResponse {
				Debug(
					fmt.Sprintf(
						"Comparing webhook URL '%s' to destination webhook '%s' in repository %s...",
						webhook.Config.URL,
						dstWebhook.Config.URL,
						repository.Name,
					),
				)
				// if the repo and URL are the same, there's a match!
				if dstWebhook.Config.URL == webhook.Config.URL {
					webhook.Exists = true
					webhook.ID = dstWebhook.ID // have to overwrite the ID for patch to work
					webhookAction = "Update"
					Debug(
						fmt.Sprintf(
							"Found matching URL %s in repository %s in destination webhooks!",
							webhook.Config.URL,
							webhook.Repository,
						),
					)
				}
			}

			if !webhook.Exists {
				webhookAction = "Create"
				Debug(
					fmt.Sprintf(
						"No matching URL %s was found in repository %s in destination webhooks.",
						webhook.Config.URL,
						webhook.Repository,
					),
				)
			}
		} else if !dstRepoExists {
			Debug(
				fmt.Sprintf(
					"Skipping URL %s because destination repository %s does not exist.",
					webhook.Config.URL,
					webhook.Repository,
				),
			)
		}

		// try to parse the webhook path from the URL the vault-path-key flag is provided
		if len(vaultPathKeys) > 0 && dstRepoExists {
			var webhookSecretPaths []string

			for _, vaultPathKey := range vaultPathKeys {
				// make sure URL contains the path key and split the URL by ?
				webhookUrlPieces := strings.Split(webhook.Config.URL, "?")
				if strings.Contains(webhook.Config.URL, vaultPathKey) && len(webhookUrlPieces) == 2 {

					// split the URL parameters by &
					webhookParameters := strings.Split(
						webhookUrlPieces[1],
						"&",
					)
					// loop pieces and find the value from the path key
					for _, piece := range webhookParameters {
						if strings.HasPrefix(piece, vaultPathKey) {
							webhookSecretPaths = append(
								webhookSecretPaths,
								strings.Replace(
									piece,
									fmt.Sprint(vaultPathKey, "="),
									"",
									1,
								),
							)
							break
						}
					}

				} else {
					missingSecrets++
					webhookSecretFound = "No parameters found in Webhook URL"
					webhookLookupSecret = false
					Debug(
						fmt.Sprintf(
							"Webhook ID %d: Vault path key provided (%s), but no matching key-value was found in webhook URL (%s)",
							webhook.ID,
							vaultPathKey,
							webhookUrl,
						),
					)
				}
			}
			webhookSecretPath = strings.Join(webhookSecretPaths[:], "/")
		}

		// only lookup when the previous step hasn't failed
		if webhookLookupSecret {
			Debug(
				fmt.Sprintf(
					"Webhook ID %d: Looking up vault secret at %s...",
					webhook.ID,
					webhookSecretPath,
				),
			)
			// try to get the webhook secret value from Vault
			foundSecret, connErr, keyErr := GetVaultSecret(webhookSecretPath)

			if connErr != nil {
				OutputError(connErr.Error(), true)
				webhookAction = "Skip: Secret lookup error"
				foundSecret = "test"
			} else if keyErr != nil {
				webhookAction = "Skip: Secret lookup error"
				missingSecrets++
				webhookSecretFound = keyErr.Error()
				Debug(
					fmt.Sprintf(
						"[ERROR] Webhook ID %d: %s",
						webhook.ID,
						webhookSecretFound,
					),
				)
			}

			if foundSecret != "" {
				webhookSecretFound = "Yes"
				webhook.Config.Secret = foundSecret
				webhook.Skip = false
			}
		}

		Debug(fmt.Sprint("Secret look-up results: ", webhookSecretFound))

		// modify output when a secret is not found
		if webhook.Skip {
			webhookName = red(webhookName)
			webhookId = red(webhookId)
			webhookUrl = red(webhookUrl)
			webhookSecretPath = red(webhookSecretPath)
			webhookSecretFound = red(webhookSecretFound)
			webhookAction = red(webhookAction)
			Debug(
				fmt.Sprintf(
					"[ERROR] Webhook ID %d: no secret found or value was empty.",
					webhook.ID,
				),
			)
		} else {
			Debug(
				fmt.Sprintf(
					"Webhook ID %d: Found secret.",
					webhook.ID,
				),
			)
		}

		// add to table data
		webhookResultsTable = append(webhookResultsTable, []string{
			webhookName,
			webhookId,
			Truncate(webhookUrl, 80),
			webhookAction,
			webhookSecretPath,
			Truncate(webhookSecretFound, 40),
		})

		// overwrite the source webhook with the new attributes
		srcWebhooksResponse[i] = webhook
	}

	// add these webhooks to the master list to process
	webhooks = append(webhooks, srcWebhooksResponse...)

	// close out this thread
	waitGroup.Done()
}

func CreateWebhook(webhook Webhook) {

	// skip if webhook is missing a secret or the destination repo doesn't exist
	if webhook.Skip {
		patchFailed++
		messagePre := fmt.Sprintf(
			"Skipping webhook ID %d because ",
			webhook.ID,
		)
		if webhook.Config.Secret == "" {
			Debug(
				fmt.Sprint(
					messagePre,
					"no secret value was found.",
				),
			)
		} else if !webhook.DstRepoExists {
			Debug(
				fmt.Sprintf(
					messagePre,
					"the destination repository %s does not exist.",
					webhook.Repository,
				),
			)
		} else {
			Debug(
				fmt.Sprint(
					messagePre,
					"of an unknown error.",
				),
			)
		}
		waitGroup.Done()
		return
	}

	// validate we have API attempts left
	timeoutErr := ValidateApiRate(dstRestClient, "core")
	if timeoutErr != nil {
		OutputError(timeoutErr.Error(), true)
	}

	// determine whether to update or create
	var action string
	var writeErr error
	if webhook.Exists {
		// update webhook
		action = "patch"
		Debug(
			fmt.Sprintf(
				"Updating webhook %s in repo %s...",
				webhook.Config.URL,
				webhook.Repository,
			),
		)
		// set up the encoding reader from the current webhook
		webhookToUpdate := WebHookPatch{
			URL:          webhook.Config.URL,
			Content_Type: webhook.Config.Content_Type,
			Insecure_SSL: webhook.Config.Insecure_SSL,
			Secret:       webhook.Config.Secret,
		}
		reader := GetReaderFromObject(webhookToUpdate)
		webhookResponse := Webhook{}
		writeErr = dstRestClient.Patch(
			fmt.Sprintf(
				"repos/%s/%s/hooks/%d/config",
				dstOrganization,
				webhook.Repository,
				webhook.ID,
			),
			reader,
			&webhookResponse,
		)
	} else {
		// create webhook
		action = "post"
		Debug(
			fmt.Sprintf(
				"Creating webhook %s in repo %s...",
				webhook.Config.URL,
				webhook.Repository,
			),
		)
		reader := GetReaderFromObject(webhook)
		webhookResponse := Webhook{}
		writeErr = dstRestClient.Post(
			fmt.Sprintf(
				"repos/%s/%s/hooks",
				dstOrganization,
				webhook.Repository,
			),
			reader,
			&webhookResponse,
		)
	}

	// validate the request worked.
	if writeErr != nil {
		patchFailed++
		Debug(
			fmt.Sprintf(
				"[ERROR] Webhook URL %s: %s failed - %s",
				webhook.Config.URL,
				action,
				writeErr.Error(),
			),
		)

	} else {
		// update success count.
		Debug(
			fmt.Sprintf(
				"Webhook URL %s : %s succeeded.",
				webhook.Config.URL,
				action,
			),
		)
		patchSucceeded++
	}

	// need to sleep after writes to avoid hitting the secondary rate limit
	time.Sleep(1 * time.Second)

	// close out this thread
	waitGroup.Done()
}

func CloneWebhooks(cmd *cobra.Command, args []string) (err error) {

	// Create log file
	logFile, err = os.Create(fmt.Sprint(time.Now().Format("20060102_150401"), ".log"))
	if err != nil {
		return err
	}
	defer logFile.Close()

	LF()
	Debug("---- VALIDATING FLAGS & ENV VARS ----")

	// Check for repos-file argument. If provided, open file.
	if len(args) != 0 {
		reposFromFile = true
		reposFilePath = args[0]
		reposFile, err = os.Open(reposFilePath)
		if err != nil {
			return err
		}
	}

	// validate flags provided
	r, _ := regexp.Compile("^http(s|):(//|)")
	if r.MatchString(srcHostname) {
		OutputError("Source hostname contains http(s) prefix and should not.", true)
	}
	if r.MatchString(dstHostname) {
		OutputError("Destination hostname contains http(s) prefix and should not.", true)
	}
	if srcOrganization == "" {
		OutputError("A source organization must be provided.", true)
	}
	if dstOrganization == "" {
		OutputError("A destination organization must be provided.", true)
	}

	// get clients set-up with the source org hostname
	opts := GetOpts(srcHostname, srcToken)
	srcRestClient, err = gh.RESTClient(&opts)
	if err != nil {
		Debug(fmt.Sprint("Error object: ", err))
		OutputError("Failed to set up source REST client. You must be logged in or provide a token.", true)
	}

	graphqlClient, err := gh.GQLClient(&opts)
	if err != nil {
		Debug(fmt.Sprint("Error object: ", err))
		OutputError("Failed set set up GraphQL client.", true)
	}
	if os.Getenv("VAULT_ADDR") == "" {
		OutputError("A valid Vault address must be provided.", true)
	}
	if os.Getenv("VAULT_TOKEN") == "" && (os.Getenv("VAULT_ROLE_ID") == "" || os.Getenv("VAULT_SECRET_ID") == "") {
		OutputError("You must provide a Vault token or Vault role ID and secret ID for authentication.", true)
	}

	// get clients set-up with the destination org hostname
	opts = GetOpts(dstHostname, dstToken)
	dstRestClient, err = gh.RESTClient(&opts)
	if err != nil {
		Debug(fmt.Sprint("Error object: ", err))
		OutputError("Failed to set up destination REST client. You must be logged in or provide a token.", true)
	}

	// attempt to validate the auth session OR provided token if it isn't an APP token
	validateUser := ""
	if !strings.HasPrefix(srcToken, "ghs_") {
		// validate an app token
		validateObject := User{}
		validateErr := srcRestClient.Get("user", &validateObject)
		if validateErr != nil {
			OutputError(validateErr.Error(), true)
		}
		validateUser = validateObject.Login
	}

	// print out information about the process
	OutputFlags("Source Host", srcHostname)
	OutputFlags("Destination Host", dstHostname)
	if validateUser != "" {
		OutputFlags("User: ", validateUser)
	}
	authMethodTitle := "Auth Method: "
	authMethod := ""
	switch {
	case srcToken == "":
		authMethod = "CLI Pass-Through"
	case srcToken != "" && strings.HasPrefix(srcToken, "gho_"):
		authMethod = "OAuth Token"
	case srcToken != "" && strings.HasPrefix(srcToken, "ghp_"):
		authMethod = "Personal Access Token"
	case srcToken != "" && strings.HasPrefix(srcToken, "ghs_"):
		authMethod = "App Token"
	default:
		authMethod = "Unknown (couldn't detect type)"
	}
	OutputFlags(authMethodTitle, authMethod)

	OutputFlags("Source Organization", srcOrganization)
	OutputFlags("Destination Organization", dstOrganization)

	vaultVersion := "2"
	if vaultKvv1 {
		vaultVersion = "1"
	}
	OutputFlags("Vault KV Version", fmt.Sprint("v", vaultVersion))

	if vaultMountpoint != "" {
		OutputFlags("Vault Mount Point", vaultMountpoint)
	}
	if len(vaultPathKeys) > 0 {
		OutputFlags("Vault Path Key", strings.Join(vaultPathKeys[:], ","))
	}
	OutputFlags("Log File", logFile.Name())
	if reposFromFile {
		OutputFlags("Input File", reposFilePath)
	}
	OutputFlags("Read Threads", strconv.Itoa(maxReadThreads))
	OutputFlags("Write Threads", strconv.Itoa(maxWriteThreads))

	// test vault connection
	vaultClient, err := GetVaultClient()
	if vaultClient == nil {
		err = errors.New(
			"Vault connection failed.",
		)
	}
	_, err = GetVaultToken(vaultClient)
	if err != nil {
		LF()
		OutputError("Connection to Vault failed.", true)
	}

	LF()

	// get our variables set up for the graphql query
	variables := map[string]interface{}{
		"owner": graphql.String(srcOrganization),
		"page":  (*graphql.String)(nil),
	}

	// Start the spinner in the CLI
	sp.Start()

	LogLF()
	Debug("---- LISTING REPOSITORIES ----")

	if reposFromFile {
		// Loop through the lines of repositories in the file
		scanner := bufio.NewScanner(reposFile)
		for scanner.Scan() {
			repoName := scanner.Text()
			repositories = append(repositories, Repository{
				Name:          repoName,
				NameWithOwner: srcOrganization + "/" + repoName,
			})
			Debug(fmt.Sprintf("Enqueuing from file repository '%s'", repoName))
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	} else {
		// Loop through pages of repositories, waiting 1 second in between
		var i = 1
		for {

			// validate we have API attempts left
			timeoutErr := ValidateApiRate(srcRestClient, "graphql")
			if timeoutErr != nil {
				OutputError(timeoutErr.Error(), true)
			}

			// show a suffix next to the spinner for what we are curretnly doing
			DebugAndStatus(
				fmt.Sprintf(
					"Fetching repositories from organization '%s' (page %d)",
					srcOrganization,
					i,
				),
			)

			// make the graphql request
			graphqlClient.Query("RepoList", &orgRepositoriesQuery, variables)

			// append repositories found to array
			repositories = append(repositories, orgRepositoriesQuery.Organization.Repositories.Nodes...)

			// if no next page is found, break
			if !orgRepositoriesQuery.Organization.Repositories.PageInfo.HasNextPage {
				break
			}
			i++

			// set the end cursor for the page we are on
			variables["page"] = &orgRepositoriesQuery.Organization.Repositories.PageInfo.EndCursor
		}
	}

	// ----------------------------------------------------------------------
	// --------- GETTING SOURCE WEBHOOKS ------------------------------------
	// ----------------------------------------------------------------------

	LogLF()
	Debug("---- GETTING WEBHOOKS ----")

	// set up table header for displaying of data
	Debug("Creating table data for display...")
	webhookResultsTable = pterm.TableData{
		{
			"Repository",
			"ID",
			"Hook URL",
			"Action",
			"Secret Path",
			"Secret Found?",
		},
	}

	// set some vars that can be adjusted in looping
	srcRepositoriesToProcess := repositories
	srcMaxRepoThreads := maxReadThreads

	// do this while there are elements left
	Debug("Batching repository webhook reads...")
	srcBatchNum := 1
	for len(srcRepositoriesToProcess) > 0 {
		// adjust number of threads
		if len(srcRepositoriesToProcess) < srcMaxRepoThreads {
			Debug(
				fmt.Sprintf(
					"Setting number of threads to %d because there are only %d repositories left.",
					len(srcRepositoriesToProcess),
					len(srcRepositoriesToProcess),
				),
			)
			srcMaxRepoThreads = len(srcRepositoriesToProcess)
		}
		DebugAndStatus(
			fmt.Sprintf(
				"Running webhook lookup batch #%d (%d threads)...",
				srcBatchNum,
				srcMaxRepoThreads,
			),
		)
		// create our batch to process from the first X elements
		batch := srcRepositoriesToProcess[:srcMaxRepoThreads]
		Debug(fmt.Sprintf("Repositories in this batch: %d", len(batch)))
		// cut those elements off of the original array
		srcRepositoriesToProcess = srcRepositoriesToProcess[len(batch):]
		Debug(fmt.Sprintf("Repositories left: %d", len(srcRepositoriesToProcess)))
		// set up our waitgroup
		Debug(
			fmt.Sprintf(
				"Creating %d repository reader threads...",
				len(batch),
			),
		)
		waitGroup.Add(len(batch))
		// do for the number of threads
		for i := 0; i < len(batch); i++ {
			Debug(
				fmt.Sprintf(
					"Running thread %d of %d for webhook lookup on repository '%s'",
					i+1,
					len(batch),
					batch[i].Name,
				),
			)
			go LookupWebhooks(batch[i])
		}
		// wait for threads to finish
		waitGroup.Wait()
		srcBatchNum++
	}

	// stop the spinner animation
	sp.Stop()

	// ---------------------------------------------------------------------
	// --------- OUTPUTTING WEBHOOKS FOUND ---------------------------------
	// ---------------------------------------------------------------------

	// show the results
	OutputNotice("Webhooks Found: ")
	Debug(fmt.Sprint(webhooks))
	LF()
	// output table
	pterm.DefaultTable.WithHasHeader().WithHeaderRowSeparator("-").WithData(webhookResultsTable).Render()
	LF()

	// ----------------------------------------------------------------------
	// --------- VALIDATE THERE ARE ANY WEBHOOKS TO UPDATE ------------------
	// ----------------------------------------------------------------------
	webhooksToSkip := 0
	for _, webhook := range webhooks {
		if webhook.Skip {
			webhooksToSkip++
		}
	}
	if webhooksToSkip == len(webhooks) {
		OutputError("No webhooks to update.", true)
	}

	// ----------------------------------------------------------------------
	// --------- PROMPTING FOR CONFIRMATION ---------------------------------
	// ----------------------------------------------------------------------

	// confirm the executor wants to proceed
	if !confirm {

		messagePrefix := "Ready to apply secrets."
		if missingSecrets > 0 {
			messagePrefix = red(
				Debug(
					fmt.Sprint(missingSecrets, " webhook(s) are missing secrets."),
				),
			)
		}
		proceedMessage := Debug("Are you sure you want to continue?")
		c, err := AskForConfirmation(fmt.Sprint(messagePrefix, " ", proceedMessage))
		if err != nil {
			OutputError(err.Error(), true)
		} else if !c {
			LF()
			OutputError("Process exited.", true)
		}
		LF()
	}

	// ----------------------------------------------------------------------
	// --------- CREATING OR UPDATING WEBHOOKS ------------------------------
	// ----------------------------------------------------------------------

	sp.Restart()
	Debug("---- CREATING OR UPDATING WEBHOOKS ----")

	// set some vars that can be adjusted in looping
	webhooksToProcess := webhooks
	maxWebhookThreads := maxWriteThreads

	// do this while there are elements left
	Debug("Batching webhook creating...")
	batchNum := 1
	for len(webhooksToProcess) > 0 {
		// adjust number of threads
		if len(webhooksToProcess) < maxWebhookThreads {
			Debug(
				fmt.Sprintf(
					"Setting number of threads to %d because there are only %d items left to process.",
					len(webhooksToProcess),
					len(webhooksToProcess),
				),
			)
			maxWebhookThreads = len(webhooksToProcess)
		}
		DebugAndStatus(
			fmt.Sprintf(
				"Running webhook creating batch #%d (%d threads)...",
				batchNum,
				maxWebhookThreads,
			),
		)
		// create our batch to process from the first X elements
		batch := webhooksToProcess[:maxWebhookThreads]
		Debug(fmt.Sprintf("Webhooks in this batch: %d", len(batch)))
		// cut those elements off of the original array
		webhooksToProcess = webhooksToProcess[len(batch):]
		Debug(fmt.Sprintf("Webhooks left: %d", len(webhooksToProcess)))
		// set up our waitgroup
		Debug(
			fmt.Sprintf(
				"Creating %d webhook creating threads...",
				len(batch),
			),
		)
		waitGroup.Add(len(batch))
		// do for the number of threads
		for i := 0; i < len(batch); i++ {
			Debug(
				fmt.Sprintf(
					"Running thread %d of %d for webhook creating ID %d",
					i+1,
					len(batch),
					batch[i].ID,
				),
			)
			go CreateWebhook(batch[i])
		}
		// wait for threads to finish
		waitGroup.Wait()
		batchNum++
	}

	sp.Stop()

	LogLF()
	Debug("---- RESULTS ----")

	if patchFailed > 0 {
		OutputError(
			fmt.Sprintf(
				"Failed to migrate secrets for %d webhook(s).",
				patchFailed,
			),
			false,
		)
	}
	if patchSucceeded > 0 {
		OutputNotice(
			fmt.Sprintf(
				"Successfully migrated secrets for %d webhook(s).",
				patchSucceeded,
			),
		)
	}

	LF()

	// always return
	return err
}
