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
	ignoreErrors        = false
	hostname            string
	organization        string
	token               string
	vaultMountpoint     string
	vaultValueKey       string
	vaultPathKey        string
	vaultToken          string
	vaultKvv1           = false
	logFile             *os.File
	maxThreads          int
	repositories        []Repository = []Repository{}
	webhooks            []Webhook    = []Webhook{}
	webhookResultsTable pterm.TableData
	waitGroup           sync.WaitGroup
	missingSecrets      int = 0

	// Create some colors and a spinner
	hiBlack = color.New(color.FgHiBlack).SprintFunc()
	reset   = color.New(color.Reset).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	cyan    = color.New(color.FgCyan).SprintFunc()
	sp      = spinner.New(spinner.CharSets[14], 40*time.Millisecond)

	// set up clients
	restClient    api.RESTClient
	graphqlClient api.GQLClient

	// Create the root cobra command
	rootCmd = &cobra.Command{
		Use:           "gh migrate-webhook-secrets",
		Short:         "GitHub CLI extension to migrate webhook secrets",
		Long:          `GitHub CLI extension to migrate webhook secrets. Supports HashiCorp Vault (KV V1 & V2) as the secret storage intermediary.`,
		Version:       "0.1.8",
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
	URL          string
	Content_Type string
	Insecure_SSL string
	Secret       string `json:"secret"`
	Token        string
	Digest       string
}

type Webhook struct {
	ID         int
	Repository string
	Name       string
	Config     WebHookConfig `json:"config"`
	Events     []string
	Active     bool
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

// Initialization function. Only happens once regardless of import.
func init() {

	// base flags
	rootCmd.PersistentFlags().StringVar(&hostname, "hostname", "github.com", "GitHub hostname")
	rootCmd.PersistentFlags().StringVar(&organization, "org", "", "Organization name")
	rootCmd.PersistentFlags().StringVar(&token, "token", "", "Optional token for authentication (uses GitHub CLI built-in authentication)")
	rootCmd.PersistentFlags().IntVar(&maxThreads, "threads", 10, "Number of threads to process at a time. WARNING: could have detrimental effects on your API rate limit.")

	// vault flags
	rootCmd.PersistentFlags().StringVar(&vaultMountpoint, "vault-mountpoint", "secret", "The mount point of the secrets on the Vault server")
	rootCmd.PersistentFlags().StringVar(&vaultPathKey, "vault-path-key", "", "The key in the webhook URL (ex: <webhook-server>?secret=<vault-path-key>) to use for finding the corresponding secret")
	rootCmd.PersistentFlags().StringVar(&vaultValueKey, "vault-value-key", "value", "The key in the Vault secret corresponding to the webhook secret value")
	rootCmd.PersistentFlags().BoolVar(&vaultKvv1, "vault-kvv1", false, "Use Vault KVv1 instead of KVv2")

	// boolean switches
	rootCmd.PersistentFlags().BoolVar(&noCache, "no-cache", false, "Disable cache for GitHub API requests")
	rootCmd.PersistentFlags().BoolVar(&confirm, "confirm", false, "Auto respond to confirmation prompt")
	rootCmd.PersistentFlags().BoolVar(&ignoreErrors, "ignore-errors", false, "Proceed regardless of errors")
}

// Main function, calls Cobra
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		ExitOnError(err)
	}
}

// Shared method for exiting on error.
func ExitOnError(err error) {
	if err != nil {
		rootCmd.PrintErrln(red(err.Error()))
		os.Exit(1)
	}
}

func OutputNotice(message string) {
	Output(message, "default", false, false)
}

func OutputError(message string, exit bool) {
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
	case color == "cyan":
		message = cyan(message)
	}
	fmt.Println(message)
	if exit {
		os.Exit(1)
	}
}

func Debug(message string) (passback string) {
	Log(message)
	passback = message
	return passback
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

// sets up the API clients for GH
func GetOpts(hostname string) (options api.ClientOptions) {
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

func ValidateApiRate(requestType string) (err error) {
	apiResponse := ApiResponse{}
	sp.Suffix = fmt.Sprint(" ", Debug("Validating API rate limits"))
	attempts := 0

	for {

		// after 240 attempts (1 hour), end the scrip.
		if attempts >= 240 {
			return errors.New("After an hour of retrying, the API rate limit has not refreshed. Aborting.")
		}

		// get the current rate liit left or error out if request fails
		err = restClient.Get("rate_limit", &apiResponse)
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
			return errors.New(fmt.Sprint("Invalid API request type provided: '", requestType, "'"))
		case requestType == "core":
			rateRemaining = apiResponse.Resources.Core.Remaining
		case requestType == "graphql":
			rateRemaining = apiResponse.Resources.Graphql.Remaining
		}
		// validate there is rate left
		if rateRemaining <= 0 {
			attempts++
			sp.Suffix = fmt.Sprint(
				" ",
				Debug(
					fmt.Sprint(
						"API rate limit (",
						requestType,
						") has none remaining. Sleeping for 15 seconds (attempt #",
						strconv.Itoa(attempts),
						")",
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

// Gets an auth token from VAULT_ROLE_ID and VAULT_SECRET_ID
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

	Debug("Determining Vault authentication method...")

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

// Looks up secrets in HashiCorp Vault
func GetVaultSecret(key string) (secret string, connErr error, pathErr error) {

	// Get the Vault client. If no vault client and no errors were returned, skip this step
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
		pathErr = errors.New(fmt.Sprint("Key '", vaultValueKey, "' not found in secret."))
	}
	return secretValue, connErr, pathErr
}

func LookupWebhooks(repository Repository) {

	// set a var to store the webhook array in
	webhooksResponse := []Webhook{}

	// print out current repository information
	sp.Suffix = fmt.Sprint(
		" ",
		Debug(
			fmt.Sprint(
				"Fetching webhooks for ",
				repository.Name,
			),
		),
	)

	// validate we have API attempts left
	timeoutErr := ValidateApiRate("core")
	if timeoutErr != nil {
		OutputError(timeoutErr.Error(), true)
	}

	// query for the webhooks on this repository
	err := restClient.Get(fmt.Sprint("repos/", repository.NameWithOwner, "/hooks"), &webhooksResponse)
	if err != nil {
		OutputError(err.Error(), true)
	}

	// add the webhooks to the table data for visibility
	for i, webhook := range webhooksResponse {
		// add the repo name the webhook
		webhook.Repository = repository.Name

		// set variables for looking up secrets
		webhookLookupSecret := true
		webhookSecretPath := repository.Name

		// set display variables
		webhookName := repository.Name
		webhookId := strconv.Itoa(webhook.ID)
		webhookUrl := webhook.Config.URL
		webhookSecretFound := "Yes"

		// try to parse the webhook path from the URL the vault-path-key flag is provided
		if vaultPathKey != "" {

			// make sure URL contains the path key and split the URL by ?
			webhookUrlPieces := strings.Split(webhook.Config.URL, "?")
			if strings.Contains(webhook.Config.URL, vaultPathKey) && len(webhookUrlPieces) == 2 {

				// split the URL parameters by &
				webhookParameters := strings.Split(webhookUrlPieces[1], "&")
				// loop pieces and find the value from the path key
				for _, piece := range webhookParameters {
					if strings.HasPrefix(piece, vaultPathKey) {
						webhookSecretPath = strings.Replace(piece, fmt.Sprint(vaultPathKey, "="), "", 1)
						break
					}
				}

			} else {
				missingSecrets++
				webhookSecretFound = "No parameters found in Webhook URL"
				webhookLookupSecret = false
			}
		}

		// only lookup when the previous step hasn't failed
		if webhookLookupSecret {
			// try to get the webhook secret value from Vault
			sp.Suffix = fmt.Sprint(
				" ",
				Debug(
					fmt.Sprintf(
						"Getting secret for webhook ID %s in repository %s",
						strconv.Itoa(webhook.ID),
						webhook.Repository,
					),
				),
			)
			foundSecret, connErr, keyErr := GetVaultSecret(webhookSecretPath)
			if connErr != nil {
				sp.Stop()
				OutputError(connErr.Error(), true)
			} else if keyErr != nil {
				missingSecrets++
				webhookSecretFound = keyErr.Error()
			}
			webhook.Config.Secret = foundSecret
		}

		Debug(fmt.Sprint("Secret look-up results: ", webhookSecretFound))

		// modify output when a secret is not found
		if webhook.Config.Secret == "" {
			webhookName = red(webhookName)
			webhookId = red(webhookId)
			webhookUrl = red(webhookUrl)
			webhookSecretPath = red(webhookSecretPath)
			webhookSecretFound = red(webhookSecretFound)
		}

		// overwrite the webhook at the index in the array
		webhooksResponse[i] = webhook

		// add to table data
		webhookResultsTable = append(webhookResultsTable, []string{
			webhookName,
			webhookId,
			webhookUrl,
			webhookSecretPath,
			webhookSecretFound,
		})
	}

	// append to the list of webooks
	webhooks = append(webhooks, webhooksResponse...)

	// close out this thread
	waitGroup.Done()
}

// GetUses returns GitHub Actions used in workflows
func CloneWebhooks(cmd *cobra.Command, args []string) (err error) {

	// Create log file
	logFile, err = os.Create(fmt.Sprint(time.Now().Format("20060102_150401"), ".log"))
	if err != nil {
		return err
	}
	defer logFile.Close()

	// validate flags provided
	r, _ := regexp.Compile("^http(s|):(//|)")
	if r.MatchString(hostname) {
		OutputError("Hostname contains http(s) prefix and should not.", true)
	}
	if organization == "" {
		OutputError("An organization must be provided.", true)
	}

	// get clients set-up with the source org hostname
	opts := GetOpts(hostname)
	restClient, err = gh.RESTClient(&opts)
	if err != nil {
		Debug(fmt.Sprint("Error object: ", err))
		OutputError("Failed to set up REST client. You must be logged in or provide a token.", true)
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

	// attempt to validate the auth session OR provided token if it isn't an APP token
	validateUser := ""
	if !strings.HasPrefix(token, "ghs_") {
		// validate an app token
		validateObject := User{}
		validateErr := restClient.Get("user", &validateObject)
		if validateErr != nil {
			OutputError(validateErr.Error(), true)
		}
		validateUser = validateObject.Login
	}

	// print out information about the process
	LF()
	OutputNotice(fmt.Sprint("Host: ", hostname))
	if validateUser != "" {
		OutputNotice(fmt.Sprint("User: ", validateUser))
	}
	authMethod := "Auth Method: "
	switch {
	case token == "":
		authMethod += "CLI Pass-Through"
	case token != "" && strings.HasPrefix(token, "gho_"):
		authMethod += "OAuth Token"
	case token != "" && strings.HasPrefix(token, "ghp_"):
		authMethod += "Personal Access Token"
	case token != "" && strings.HasPrefix(token, "ghs_"):
		authMethod += "App Token"
	default:
		authMethod += "Unknown (couldn't detect type)"
	}
	OutputNotice(authMethod)
	OutputNotice(fmt.Sprint("Organization: ", organization))

	vaultVersion := "2"
	if vaultKvv1 {
		vaultVersion = "1"
	}
	OutputNotice(fmt.Sprint("Vault KV Version: ", "v", vaultVersion))

	if vaultMountpoint != "" {
		OutputNotice(fmt.Sprint("Vault Mount Point: ", vaultMountpoint))
	}
	if vaultPathKey != "" {
		OutputNotice(fmt.Sprint("Vault Path Key: ", vaultPathKey))
	}

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
		"owner": graphql.String(organization),
		"page":  (*graphql.String)(nil),
	}

	// Start the spinner in the CLI
	sp.Start()

	// Loop through pages of repositories, waiting 1 second in between
	var i = 1
	for {

		// validate we have API attempts left
		timeoutErr := ValidateApiRate("graphql")
		if timeoutErr != nil {
			OutputError(timeoutErr.Error(), true)
		}

		// show a suffix next to the spinner for what we are curretnly doing
		sp.Suffix = fmt.Sprint(
			" ",
			Debug(
				fmt.Sprint(
					"Fetching repositories from ",
					organization,
					" (page ",
					i,
					")",
				),
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

	// set up table header for displaying of data
	sp.Suffix = fmt.Sprint(
		" ",
		Debug("Creating table data for display."),
	)
	webhookResultsTable = pterm.TableData{
		{
			"Repository",
			"ID",
			"Hook URL",
			"Secret Path",
			"Secret Found?",
		},
	}

	// set some vars that can be adjusted in looping
	repositoriesToProcess := repositories
	maxRepoThreads := maxThreads

	// do this while there are elements left
	Debug("Batching repository webhook reads...")
	batchNum := 1
	for len(repositoriesToProcess) > 0 {
		Debug(fmt.Sprintf("Starting batch #%d", batchNum))
		// adjust number of threads
		if len(repositoriesToProcess) < maxRepoThreads {
			Debug(
				fmt.Sprintf(
					"Setting number of threads to %d because there are only %d repositories left.",
					len(repositoriesToProcess),
					len(repositoriesToProcess),
				),
			)
			maxRepoThreads = len(repositoriesToProcess)
		}
		// create our batch to process from the first X elements
		batch := repositoriesToProcess[:maxRepoThreads]
		Debug(fmt.Sprintf("Repositories in this batch: %d", len(batch)))
		// cut those elements off of the original array
		repositoriesToProcess = repositoriesToProcess[len(batch):]
		Debug(fmt.Sprintf("Repositories left: %d", len(repositoriesToProcess)))
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
					"Launching webhooks lookup go routine (%d of %d) for repository '%s'",
					i+1,
					len(batch),
					batch[i].NameWithOwner,
				),
			)
			go LookupWebhooks(batch[i])
		}
		// wait for threads to finish
		waitGroup.Wait()
		batchNum++
	}

	// stop the spinner animation
	sp.Stop()

	// show the results
	OutputNotice("Webhooks Found: ")
	Debug(fmt.Sprint(webhooks))
	LF()
	// output table
	pterm.DefaultTable.WithHasHeader().WithHeaderRowSeparator("-").WithData(webhookResultsTable).Render()
	LF()

	// confirm the executor wants to proceed
	if !confirm {

		messagePrefix := "Ready to apply secrets."
		if missingSecrets > 0 {
			messagePrefix = red(Debug(fmt.Sprint(missingSecrets, " webhook(s) are missing secrets.")))
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

	sp.Restart()
	sp.Suffix = fmt.Sprint(
		" ",
		Debug("Beginning patching of Webhooks..."),
	)

	// loop through all webhooks
	var success = 0
	var failed = 0
	for _, webhook := range webhooks {

		// skip bad webhooks
		if webhook.Config.Secret == "" {
			failed++
			Debug("Skipping webhook because no secret value was found.")
			continue
		}

		// validate we have API attempts left
		timeoutErr := ValidateApiRate("core")
		if timeoutErr != nil {
			OutputError(timeoutErr.Error(), true)
		}

		// output what's current processing
		sp.Suffix = fmt.Sprint(
			" ",
			Debug(
				fmt.Sprintf(
					"Creating webhook to %s in repository %s",
					webhook.Config.URL,
					webhook.Repository,
				),
			),
		)

		// set up the encoding reader from the current webhook
		var webhookToUpdate = WebHookPatch{
			URL:          webhook.Config.URL,
			Content_Type: webhook.Config.Content_Type,
			Insecure_SSL: webhook.Config.Insecure_SSL,
			Secret:       webhook.Config.Secret,
		}

		// convert the struct to io.reader
		data, err := json.Marshal(&webhookToUpdate)
		if err != nil {
			sp.Stop()
			OutputError(err.Error(), true)
		}
		reader := bytes.NewReader(data)

		// post the request
		webhookResponse := Webhook{}
		err = restClient.Patch(
			fmt.Sprint(
				"repos/",
				organization,
				"/",
				webhook.Repository,
				"/hooks/",
				webhook.ID,
				"/config",
			),
			reader,
			&webhookResponse,
		)

		// validate the request worked.
		if err != nil {

			failed++

			// stop and output the error
			sp.Stop()
			OutputError(err.Error(), false)
			LF()

			// if autoproceed is not enabled, prompt user
			if !ignoreErrors {
				c, err := AskForConfirmation("Do you want to proceed?")
				LF()
				if err != nil {
					OutputError(err.Error(), true)
				}
				if !c {
					LF()
					OutputError("Process exited.", true)
				}
			}

			// restart the spinner
			sp.Start()
		} else {
			// update success count.
			Debug("Successfully updated secret.")
			success++
		}

		// need to sleep after writes to avoid hitting the secondary rate limit
		time.Sleep(1 * time.Second)
	}
	sp.Stop()

	if failed > 0 {
		OutputError(fmt.Sprint("Failed to migrate secrets for ", failed, " webhook(s)"), false)
	}

	if success > 0 {
		OutputNotice(fmt.Sprint("Successfully migrated secrets for ", success, " webhook(s)."))
	}

	return err
}
