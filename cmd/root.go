package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
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
	"github.com/pterm/pterm"
	"github.com/shurcooL/graphql"
	"github.com/spf13/cobra"
)

var (

	// Set up main variables
	noCache             = false
	confirmProceed      = false
	autoProceed         = false
	sourceHostname      string
	sourceOrg           string
	destinationHostname string
	destinationOrg      string

	// Create some colors and a spinner
	hiBlack = color.New(color.FgHiBlack).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	cyan    = color.New(color.FgCyan).SprintFunc()
	sp      = spinner.New(spinner.CharSets[14], 40*time.Millisecond)

	// set up clients
	restClient    api.RESTClient
	graphqlClient api.GQLClient

	// Create the root cobra command
	rootCmd = &cobra.Command{
		Use:     "gh-clone-webhooks",
		Short:   "gh cli extension to clone webhooks",
		Long:    `gh cli extension to clone webhooks from one org to another.`,
		Version: "0.0.0-development",
		RunE:    CloneWebhooks,
	}

	orgRepositoriesQuery struct {
		Organization struct {
			Repositories Repos `graphql:"repositories(first: 100, after: $page, orderBy: {field: NAME, direction: ASC})"`
		} `graphql:"organization(login: $owner)"`
	}

	repositories []Repository
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
	Name             string
	NameWithOwner    string
	Owner            Organization
	Description      string
	URL              string
	Visibility       string
	IsArchived       bool
	IsTemplate       bool
	DefaultBranchRef struct {
		Name string
	}
	HasIssuesEnabled   bool
	HasProjectsEnabled bool
	HasWikiEnabled     bool
	IsFork             bool
	ForkCount          int
	ForkingAllowed     bool
	DiskUsage          int
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type Webhook struct {
	ID         int
	Repository string
	Type       string
	Name       string
	Active     bool
	Events     []string
	Config     struct {
		Content_Type string
		Insecure_SSL string
		URL          string
		Secret       string
		Token        string
		Digest       string
	}
}

// Initialization function. Only happens once regardless of import.
func init() {
	// declare flags available to executor
	rootCmd.PersistentFlags().StringVar(&sourceHostname, "source-hostname", "github.com", "Source GitHub hostname.")
	rootCmd.PersistentFlags().StringVar(&sourceOrg, "source-org", "", "Source organization name.")
	rootCmd.PersistentFlags().StringVar(&destinationHostname, "destination-hostname", "github.com", "Destination GitHub hostname.")
	rootCmd.PersistentFlags().StringVar(&destinationOrg, "destination-org", "", "Destination organization name")
	rootCmd.PersistentFlags().BoolVar(&noCache, "disable-cache", false, "Disable cache for GitHub API requests.")
	rootCmd.PersistentFlags().BoolVar(&confirmProceed, "confirm", false, "Auto respond to confirmation prompt.")
	rootCmd.PersistentFlags().BoolVar(&autoProceed, "auto-proceed", false, "Proceed regardless of errors.")
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
	reader := bufio.NewReader(os.Stdin)

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

// GetUses returns GitHub Actions used in workflows
func CloneWebhooks(cmd *cobra.Command, args []string) (err error) {

	// set up API clients
	opts := api.ClientOptions{
		Host:        sourceHostname,
		EnableCache: !noCache,
		CacheTTL:    time.Hour,
	}

	restClient, _ = gh.RESTClient(&opts)
	graphqlClient, _ = gh.GQLClient(&opts)

	r, _ := regexp.Compile("^http(s|)://")

	if r.MatchString(sourceHostname) {
		return fmt.Errorf("Source hostname contains http(s) prefix and should not.")
	}
	if r.MatchString(destinationHostname) {
		return fmt.Errorf("Destination hostname contains http(s) prefix and should not.")
	}
	if sourceOrg == "" {
		return fmt.Errorf("A source organization must be provided.")
	}
	if destinationOrg == "" {
		return fmt.Errorf("A destination organization must be provided.")
	}

	fmt.Println()
	fmt.Println(cyan("Source: ") + sourceHostname + "/" + sourceOrg)
	fmt.Println(cyan("Destination: ") + destinationHostname + "/" + destinationOrg)
	fmt.Println()

	variables := map[string]interface{}{
		"owner": graphql.String(sourceOrg),
		"page":  (*graphql.String)(nil),
	}

	// Start the spinner in the CLI
	sp.Start()

	// Loop through pages of repositories, waiting 1 second in between
	var i = 1
	for {

		// show a suffix next to the spinner for what we are curretnly doing
		sp.Suffix = fmt.Sprintf(
			" fetching repositories from %s %s",
			sourceOrg,
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

		// increment for spinner suffix visibility
		i++

		// sleep for 1 second to avoid rate limiting
		time.Sleep(1 * time.Second)

		// set the end cursor for the page we are on
		variables["page"] = &orgRepositoriesQuery.Organization.Repositories.PageInfo.EndCursor
	}

	// set up table header for displaying of data
	sp.Suffix = fmt.Sprintf(" creating table data for display.")
	var td = pterm.TableData{
		{"Repository", "ID", "URL", "Active", "Content Type", "Events"},
	}

	// Loop through repositories and get webhooks
	webhooks := []Webhook{}
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
			// overwrite the webhook at the index in the array
			webhooksResponse[i] = webhook
			// add to table data
			td = append(td, []string{
				repo.Name,
				strconv.Itoa(webhook.ID),
				webhook.Config.URL,
				strconv.FormatBool(webhook.Active),
				webhook.Config.Content_Type,
				strings.Join(webhook.Events, ","),
			})
		}

		// append to the list of webooks
		webhooks = append(webhooks, webhooksResponse...)

		// sleep for 1 second to avoid rate limiting
		time.Sleep(1 * time.Second)
	}

	// stop the spinner animation
	sp.Stop()

	// show the results
	fmt.Println(cyan("Webhooks Found: "))
	fmt.Println()
	pterm.DefaultTable.WithHasHeader().WithHeaderRowSeparator("-").WithData(td).Render()
	fmt.Println()

	// confirm the executor wants to proceed
	if !confirmProceed {
		c := askForConfirmation("Do you want to clone all webhooks to org " + destinationHostname + "/" + destinationOrg + "?")
		if !c {
			fmt.Println()
			fmt.Println("Process exited.")
			return err
		}
		fmt.Println()
	}

	// point REST client to destination
	opts.Host = destinationHostname
	restClient, _ = gh.RESTClient(&opts)

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
		type configBlock struct {
			URL          string `json:"url"`
			Content_Type string `json:"content_type"`
			Insecure_SSL string `json:"insecure_ssl"`
			Secret       string `json:"secret"`
			Token        string `json:"token"`
			Digest       string `json:"digest"`
		}
		type webhookPayload struct {
			Name   string      `json:"name"`
			Config configBlock `json:"config"`
			Events []string    `json:"events"`
			Active bool        `json:"active"`
		}
		var webhookToCreate = webhookPayload{
			Name: webhook.Name,
			Config: configBlock{
				URL:          webhook.Config.URL,
				Content_Type: webhook.Config.Content_Type,
				Insecure_SSL: webhook.Config.Insecure_SSL,
				Secret:       "value-from-vault",
				Token:        webhook.Config.Token,
				Digest:       webhook.Config.Digest,
			},
			Events: webhook.Events,
			Active: webhook.Active,
		}

		// convert the struct to io.reader
		data, err := json.Marshal(&webhookToCreate)
		if err != nil {
			sp.Stop()
			return err
		}
		reader := bytes.NewReader(data)

		// post the request
		webhookResponse := Webhook{}
		err = restClient.Post("repos/"+destinationOrg+"/"+webhook.Repository+"/hooks", reader, &webhookResponse)

		// validate the request worked.
		if err != nil {

			// stop and output the error
			sp.Stop()
			fmt.Println(red(err))
			fmt.Println()

			// if autoproceed is not enabled, prompt user
			if !autoProceed {
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

		// sleep for 1 second to avoid rate limiting
		time.Sleep(1 * time.Second)
	}
	sp.Stop()

	// send back result to user
	fmt.Println("Webhook cloning completed. " + strconv.Itoa(success) + " webhooks cloned.")

	return err
}
