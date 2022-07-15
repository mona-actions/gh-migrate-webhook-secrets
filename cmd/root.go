package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
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
	noCache         = false
	confirm         = false
	ignoreErrors    = false
	hostname        string
	organization    string
	token           string
	vaultMountpoint string
	vaultValueKey   string
	vaultPathKey    string
	vaultKvv1       = false

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
		Version:       "0.1.1",
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

func askForConfirmation(s string) bool {
	// read the input
	reader := bufio.NewReader(os.Stdin)
	// loop until a response is valid
	for {
		fmt.Printf("%s [y/n]: ", s)
		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		response = strings.ToLower(strings.TrimSpace(response))
		if response == "y" || response == "yes" {
			return true
		} else if response == "n" || response == "no" {
			return false
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

	// Get security credentials from environment
	vaultToken := os.Getenv("VAULT_TOKEN")
	vaultRoleId := os.Getenv("VAULT_ROLE_ID")
	vaultSecretId := os.Getenv("VAULT_SECRET_ID")

	// determine if we should auth with role id and secret id
	if vaultRoleId != "" && vaultSecretId != "" {
		vaultToken, err = AuthUser(client, vaultRoleId, vaultSecretId)
		if err != nil {
			return "", err
		}
	}

	// validate a token exists
	if vaultToken == "" {
		err = errors.New(
			"No valid authentication was provided. Either 'VAULT_TOKEN' or  'VAULT_ROLE_ID' & 'VAULT_SECRET_ID' must be defined.",
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

	// get the token
	vaultToken, connErr := GetVaultToken(vaultClient)
	if connErr != nil {
		return "", connErr, pathErr
	}

	// authenticate
	vaultClient.SetToken(vaultToken)

	var secretValue = ""
	var secretInterface interface{}
	var foundKey bool = false

	if vaultKvv1 {
		// query using kvv1
		kvv1Response, pathErr := vaultClient.KVv1(vaultMountpoint).Get(context.Background(), "data/"+key)
		if pathErr != nil {
			return "", connErr, pathErr
		}
		secretResponse := kvv1Response.Data["data"]
		for k, v := range secretResponse.(map[string]interface{}) {
			if k == vaultValueKey {
				secretInterface = v
				foundKey = true
				break
			}
		}

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
		pathErr = errors.New("Key '" + vaultValueKey + "' not found in secret.")
	}
	return secretValue, connErr, pathErr
}

// GetUses returns GitHub Actions used in workflows
func CloneWebhooks(cmd *cobra.Command, args []string) (err error) {

	// get clients set-up with the source org hostname
	opts := GetOpts(hostname)
	restClient, restErr := gh.RESTClient(&opts)
	if restErr != nil {
		fmt.Println(red("Failed set set up REST client."))
		return restErr
	}

	graphqlClient, graphqlErr := gh.GQLClient(&opts)
	if graphqlErr != nil {
		fmt.Println(red("Failed set set up GraphQL client."))
		return graphqlErr
	}

	// create a regex filter to make sure http(s) isn't added
	r, _ := regexp.Compile("^http(s|)://")

	// validate flags provided
	if r.MatchString(hostname) {
		return fmt.Errorf("Hostname contains http(s) prefix and should not.")
	}
	if organization == "" {
		return fmt.Errorf("An organization must be provided.")
	}
	if os.Getenv("VAULT_ADDR") == "" {
		return fmt.Errorf("A valid Vault address must be provided.")
	}
	if os.Getenv("VAULT_TOKEN") == "" && (os.Getenv("VAULT_ROLE_ID") == "" || os.Getenv("VAULT_SECRET_ID") == "") {
		return fmt.Errorf("You must provide a Vault token or Vault role ID and secret ID for authentication.")
	}

	// print out information about the process
	fmt.Println()
	fmt.Println(cyan("Host: ") + hostname)
	fmt.Println(cyan("Organization: ") + organization)

	vaultVersion := "2"
	if vaultKvv1 {
		vaultVersion = "1"
	}
	fmt.Println(cyan("Vault KV Version: ") + "v" + vaultVersion)

	if vaultMountpoint != "" {
		fmt.Println(cyan("Vault Mount Point: ") + vaultMountpoint)
	}
	if vaultPathKey != "" {
		fmt.Println(cyan("Vault Path Key: ") + vaultPathKey)
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
		fmt.Println()
		fmt.Println("Connection to Vault failed.")
		return err
	}

	fmt.Println()
	fmt.Println()

	// get our variables set up for the graphql query
	variables := map[string]interface{}{
		"owner": graphql.String(organization),
		"page":  (*graphql.String)(nil),
	}

	// Start the spinner in the CLI
	sp.Start()

	// Loop through pages of repositories, waiting 1 second in between
	repositories := []Repository{}
	var i = 1
	for {

		// show a suffix next to the spinner for what we are curretnly doing
		sp.Suffix = fmt.Sprintf(
			" fetching repositories from %s %s",
			organization,
			hiBlack(fmt.Sprintf("(page %d)", i)),
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
	sp.Suffix = fmt.Sprintf(" creating table data for display.")
	var td = pterm.TableData{
		{
			"Repository",
			"ID",
			"Hook URL",
			"Secret Path",
			"Secret Found?",
		},
	}

	// Loop through repositories and get webhooks
	webhooks := []Webhook{}
	var missingSecrets = 0
	for _, repo := range repositories {

		// set a var to store the webhook array in
		webhooksResponse := []Webhook{}

		// print out current repository information
		sp.Suffix = fmt.Sprintf(
			" fetching webhooks for %s",
			repo.Name,
		)

		// query for the webhooks on this repository
		err = restClient.Get("repos/"+repo.NameWithOwner+"/hooks", &webhooksResponse)
		if err != nil {
			return err
		}

		// add the webhooks to the table data for visibility
		for i, webhook := range webhooksResponse {
			// add the repo name the webhook
			webhook.Repository = repo.Name

			// set variables for looking up secrets
			webhookLookupSecret := true
			webhookSecretPath := repo.Name

			// set display variables
			webhookName := repo.Name
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
							webhookSecretPath = strings.Replace(piece, vaultPathKey+"=", "", 1)
							break
						}
					}

				} else {
					missingSecrets++
					webhookSecretFound = red("No parameters found in Webhook URL")
					webhookLookupSecret = false
				}
			}

			// only lookup when the previous step hasn't failed
			if webhookLookupSecret {
				// try to get the webhook secret value from Vault
				sp.Suffix = fmt.Sprintf(
					" getting secret for webhook %s in repository %s",
					webhook.Config.URL,
					webhook.Repository,
				)
				foundSecret, connErr, keyErr := GetVaultSecret(webhookSecretPath)
				if connErr != nil {
					sp.Stop()
					return connErr
				} else if keyErr != nil {
					missingSecrets++
					webhookSecretFound = red(keyErr)
				}
				webhook.Config.Secret = foundSecret
			}

			// modify output when a secret is not found
			if webhook.Config.Secret == "" {
				webhookName = red(webhookName)
				webhookId = red(webhookId)
				webhookUrl = red(webhookUrl)
				webhookSecretPath = red(webhookSecretPath)
			}

			// overwrite the webhook at the index in the array
			webhooksResponse[i] = webhook

			// add to table data
			td = append(td, []string{
				webhookName,
				webhookId,
				webhookUrl,
				webhookSecretPath,
				webhookSecretFound,
			})
		}

		// append to the list of webooks
		webhooks = append(webhooks, webhooksResponse...)
	}

	// stop the spinner animation
	sp.Stop()

	// show the results
	fmt.Println(cyan("Webhooks Found: "))
	fmt.Println()
	pterm.DefaultTable.WithHasHeader().WithHeaderRowSeparator("-").WithData(td).Render()
	fmt.Println()

	// confirm the executor wants to proceed
	if !confirm {

		messagePrefix := "Ready to apply secrets."
		if missingSecrets > 0 {
			messagePrefix = red(strconv.Itoa(missingSecrets) + " webhook(s) are missing secrets.")
		}

		c := askForConfirmation(messagePrefix + " Are you sure you want to continue?")
		if !c {
			fmt.Println()
			fmt.Println("Process exited.")
			return err
		}
		fmt.Println()
	}

	sp.Restart()
	sp.Suffix = fmt.Sprintf("Beginning cloning of Webhooks...")

	// loop through all webhooks
	var success = 0
	for _, webhook := range webhooks {

		// output what's current processing
		sp.Suffix = fmt.Sprintf(
			" creating webhook to %s in repository %s",
			webhook.Config.URL,
			webhook.Repository,
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
			return err
		}
		reader := bytes.NewReader(data)

		// post the request
		webhookResponse := Webhook{}
		err = restClient.Patch(
			"repos/"+organization+"/"+webhook.Repository+"/hooks/"+strconv.Itoa(webhook.ID)+"/config",
			reader,
			&webhookResponse,
		)

		// validate the request worked.
		if err != nil {

			// stop and output the error
			sp.Stop()
			fmt.Println(red(err))
			fmt.Println()

			// if autoproceed is not enabled, prompt user
			if !ignoreErrors {
				c := askForConfirmation("Do you want to proceed?")
				fmt.Println()
				if !c {
					fmt.Println("Process exited.")
					os.Exit(1)
				}
			}

			// restart the spinner
			sp.Start()
		} else {
			// update success count.
			success++
		}
	}
	sp.Stop()

	// send back result to user
	fmt.Println("Successfully migrated secrets for " + strconv.Itoa(success) + " webhook(s).")

	return err
}
