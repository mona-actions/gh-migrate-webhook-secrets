package cmd

import (
	"fmt"
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
	sourceHostname      string
	sourceOrg           string
	destinationHostname string
	destinationOrg      string

	// Create some colors and a spinner
	hiBlack = color.New(color.FgHiBlack).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
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
	}
}

// Initialization function. Only happens once regardless of import.
func init() {

	// initialize with the config
	cobra.OnInitialize(initConfig)

	// declare flags available to executor
	rootCmd.PersistentFlags().StringVar(&sourceHostname, "source-hostname", "github.com", "Source GitHub hostname.")
	rootCmd.PersistentFlags().StringVar(&sourceOrg, "source-org", "", "Source organization name.")
	rootCmd.PersistentFlags().StringVar(&destinationHostname, "destination-hostname", "github.com", "Destination GitHub hostname.")
	rootCmd.PersistentFlags().StringVar(&destinationOrg, "destination-org", "", "Destination organization name")
	rootCmd.PersistentFlags().BoolVar(&noCache, "disable-cache", false, "Disable cache for GitHub API requests.")
}

// Initialization configuration
func initConfig() {

	opts := api.ClientOptions{
		Host:        sourceHostname,
		EnableCache: !noCache,
		CacheTTL:    time.Hour,
	}

	restClient, _ = gh.RESTClient(&opts)
	graphqlClient, _ = gh.GQLClient(&opts)
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

// GetUses returns GitHub Actions used in workflows
func CloneWebhooks(cmd *cobra.Command, args []string) (err error) {

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

	fmt.Println("Source: " + sourceHostname + "/" + sourceOrg)
	fmt.Println("Destination: " + destinationHostname + "/" + destinationOrg)

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

	// Loop through repositories and get webhooks
	var td = pterm.TableData{
		{"Repository", "ID", "URL", "Active", "Content Type", "Events"},
	}
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

		// add the repo name as a property on the webhook (for later use)
		for i, webhook := range webhooksResponse {
			webhooksResponse[i].Repository = repo.Name
			td = append(td, []string{
				repo.Name,
				strconv.Itoa(webhook.ID),
				webhook.Config.URL,
				strconv.FormatBool(webhook.Active),
				webhook.Config.Content_Type,
				strings.Join(webhook.Events, ","),
			})
		}

		// merge the list of arrays
		webhooks = append(webhooks, webhooksResponse...)

		// sleep for 1 second to avoid rate limiting
		time.Sleep(1 * time.Second)
	}

	// stop the spinner animation
	sp.Stop()

	// show the results
	pterm.DefaultTable.WithHasHeader().WithHeaderRowSeparator("-").WithData(td).Render()
	// fmt.Println(webhooks)

	return err
}
