package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/goccy/go-yaml"
	"log"
	"time"
)

var (
	configPath   string
	manifestPath string
)

type Config struct {
}
type StorageAccountTarget struct {
	Name                    string                              `json:"name"`
	AccountCreateParameters *armstorage.AccountCreateParameters `json:"accountCreateParameters,omitempty"`
}
type Manifest struct {
	SubscriptionId string                      `json:"subscriptionId"`
	ResourceGroup  *armresources.ResourceGroup `json:"resourceGroup"`
	StorageAccount *StorageAccountTarget       `json:"storageAccount,omitempty"`
	AppServicePlan *armappservice.Plan         `json:"appServicePlan,omitempty"`
	FunctionApp    []*armappservice.Site       `json:"functionApp"`
}
type State struct {
	AppServicePlan *armappservice.Plan
	StorageAccount *armstorage.Account
	FunctionApp    []*armappservice.Site
	ResourceGroup  *armresources.ResourceGroup
}

var (
	config   *Config
	manifest *Manifest
	state    *State
)
var (
	cred                 azcore.TokenCredential
	resourceGroupClient  *armresources.ResourceGroupsClient
	accountStorageClient *armstorage.AccountsClient
	planClient           *armappservice.PlansClient
	webAppClient         *armappservice.WebAppsClient
	deploymentClient     *armresources.DeploymentsClient
	cleanup              = false
)

func main() {
	cmd := &cobra.Command{
		Use:   os.Args[0],
		Short: "Test Azure",
		RunE: func(cmd *cobra.Command, args []string) error {
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
			defer signal.Stop(ch)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				select {
				case s := <-ch:
					log.Printf("Received signal: %s", s.String())
					cancel()
				case <-ctx.Done():
				}
			}()
			return run(ctx)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "config file path")
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "manifest file path")
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	var err error
	if manifest, err = loadManifest(manifestPath); err != nil {
		return err
	}
	if config, err = loadConfig(configPath); err != nil {
		return err
	}
	if cred, err = loadCredential(); err != nil {
		return err
	}
	if err = initializeClient(); err != nil {
		return err
	}
	state = &State{}
	if err = ensureResourceGroup(ctx); err != nil {
		return err
	}
	defer cleanupResourceGroup(ctx)
	if err = ensureStorageAccount(ctx); err != nil {
		return err
	}
	defer cleanupStorageAccount(ctx)
	//if err = ensureAppServicePlan(ctx); err != nil {
	//	return err
	//}
	//defer cleanupAppServicePlan(ctx)
	if err = ensureFunctionApp(ctx); err != nil {
		return err
	}

	//deploymentClient.BeginCreateOrUpdate(ctx, state.ResourceGroup.Name, armresources.Deployment{})
	//
	//deploy,err := deploymentClient.BeginCreateOrUpdate(
	//  ctx,
	//  resourceGroupName,
	//  deploymentName,
	//  armresources.Deployment{
	//    Properties: &armresources.DeploymentProperties{
	//
	//    }
	//  },
	//  nil,
	//  )
	return nil
}
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	jsonData, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(jsonData, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
func loadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest Manifest
	jsonData, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(jsonData, &manifest)
	if err != nil {
		return nil, err
	}
	return &manifest, nil
}
func loadCredential() (azcore.TokenCredential, error) {
	return azidentity.NewDefaultAzureCredential(nil)
}
func initializeClient() error {
	var err error
	resourceGroupClient, err = armresources.NewResourceGroupsClient(manifest.SubscriptionId, cred, nil)
	if err != nil {
		return err
	}
	accountStorageClient, err = armstorage.NewAccountsClient(manifest.SubscriptionId, cred, nil)
	if err != nil {
		return err
	}
	planClient, err = armappservice.NewPlansClient(manifest.SubscriptionId, cred, nil)
	if err != nil {
		return err
	}
	webAppClient, err = armappservice.NewWebAppsClient(manifest.SubscriptionId, cred, nil)
	if err != nil {
		return err
	}
	return nil
}
func ensureResourceGroup(ctx context.Context) error {
	resp, err := resourceGroupClient.Get(ctx, *manifest.ResourceGroup.Name, nil)
	var notFound *azcore.ResponseError
	if err != nil {
		if errors.As(err, &notFound) && notFound.StatusCode == 404 {
			resp, err := resourceGroupClient.CreateOrUpdate(
				ctx,
				*manifest.ResourceGroup.Name,
				*manifest.ResourceGroup,
				nil)
			if err != nil {
				return err
			}
			state.ResourceGroup = &resp.ResourceGroup
			return nil
		} else {
			return err
		}
	} else {
		//TODO: compare to bring resourceGroup up to date
		state.ResourceGroup = &resp.ResourceGroup
		return nil
	}
}
func cleanupResourceGroup(ctx context.Context) {
	if !cleanup {
		return
	}
	poller, err := resourceGroupClient.BeginDelete(ctx, *state.ResourceGroup.Name, nil)
	if err != nil {
		log.Panicf("failed to begin delete resource group: %v", err)
	}
	if _, err = poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 30 * time.Second}); err != nil {
		log.Panicf("failed to poll delete resource group: %v", err)
	}
}
func ensureStorageAccount(ctx context.Context) error {
	resp, err := accountStorageClient.GetProperties(ctx, *state.ResourceGroup.Name, manifest.StorageAccount.Name, nil)
	if err != nil {
		var notFound *azcore.ResponseError
		if errors.As(err, &notFound) && notFound.StatusCode == 404 {
			if manifest.StorageAccount.AccountCreateParameters == nil ||
				manifest.StorageAccount.AccountCreateParameters.Kind == nil ||
				manifest.StorageAccount.AccountCreateParameters.SKU == nil {
				return errors.New("missing required parameters for storage account")
			}
			if manifest.StorageAccount.AccountCreateParameters.Location == nil {
				manifest.StorageAccount.AccountCreateParameters.Location = manifest.ResourceGroup.Location
			}
			pollerResp, err := accountStorageClient.BeginCreate(
				ctx,
				*state.ResourceGroup.Name,
				manifest.StorageAccount.Name,
				*manifest.StorageAccount.AccountCreateParameters, nil)
			if err != nil {
				return err
			}
			resp, err := pollerResp.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
			if err != nil {
				return err
			}
			//TODO: compare to bring storage account up to date
			state.StorageAccount = &resp.Account
			return nil
		} else {
			return err
		}
	} else {
		state.StorageAccount = &resp.Account
		return nil
	}
}
func cleanupStorageAccount(ctx context.Context) {
	if !cleanup {
		return
	}
	if _, err := accountStorageClient.Delete(ctx, *state.ResourceGroup.Name, *state.StorageAccount.Name, nil); err != nil {
		log.Panicf("failed to delete storage account: %v", err)
	}
}
func ensureAppServicePlan(ctx context.Context) error {
	if manifest.AppServicePlan == nil {
		return nil
	}
	resp, err := planClient.Get(ctx, *state.ResourceGroup.Name, *manifest.AppServicePlan.Name, nil)
	var notFound *azcore.ResponseError
	if err != nil {
		if errors.As(err, &notFound) && notFound.StatusCode == 404 {
			poller, err := planClient.BeginCreateOrUpdate(
				ctx,
				*manifest.ResourceGroup.Name,
				*manifest.AppServicePlan.Name,
				*manifest.AppServicePlan,
				nil)
			if err != nil {
				return err
			}
			resp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
			if err != nil {
				return err
			}
			state.AppServicePlan = &resp.Plan
			return nil
		} else {
			return err
		}
	} else {
		//TODO: compare to bring app service plan up to date
		state.AppServicePlan = &resp.Plan
		return nil
	}
}
func cleanupAppServicePlan(ctx context.Context) {
	if !cleanup {
		return
	}
	if state.AppServicePlan == nil {
		return
	}
	if _, err := planClient.Delete(ctx, *state.ResourceGroup.Name, *state.AppServicePlan.Name, nil); err != nil {
		log.Panicf("failed to delete app service plan for resource group %s: %v", *state.ResourceGroup.Name, err)
	}
}
func getStorageAccountKey(ctx context.Context) (string, error) {
	keyResp, err := accountStorageClient.ListKeys(ctx,
		*state.ResourceGroup.Name,
		*state.StorageAccount.Name,
		nil)
	if err != nil {
		return "", err
	}
	return *keyResp.Keys[0].Value, nil
}
func ensureFunctionApp(ctx context.Context) error {
	pager := webAppClient.NewListByResourceGroupPager(*state.ResourceGroup.Name, nil)
	existFunctionApp := make(map[string]*armappservice.Site)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, site := range page.Value {
			if site.Kind != nil && strings.Contains(*site.Kind, "functionapp") {
				existFunctionApp[*site.Name] = site
			}
		}
	}
	state.FunctionApp = make([]*armappservice.Site, len(manifest.FunctionApp))
	key, err := getStorageAccountKey(ctx)
	if err != nil {
		return err
	}
	connStr := fmt.Sprintf("DefaultEndpointsProtocol=https;AccountName=%s;AccountKey=%s;EndpointSuffix=%s",
		*state.StorageAccount.Name,
		key,
		"core.windows.net",
		//strings.TrimPrefix(*state.StorageAccount.Properties.PrimaryEndpoints.Blob, fmt.Sprintf("https://%s.blob.", state.StorageAccount.Name)),
	)
	for idx, targetFunctionApp := range manifest.FunctionApp {
		if fa, ok := existFunctionApp[*targetFunctionApp.Name]; ok {
			//TODO: compare to bring function app up to date
			state.FunctionApp[idx] = fa
			continue
		}
		targetFunctionApp.Location = state.ResourceGroup.Location
		name := *targetFunctionApp.Name
		if len(name) > 50 {
			name = name[:50]
		}
		uuidStr := uuid.New().String()
		name = strings.ToLower(name + uuidStr[len(uuidStr)-12:])
		targetFunctionApp.Properties.SiteConfig.AppSettings = append(targetFunctionApp.Properties.SiteConfig.AppSettings,
			&armappservice.NameValuePair{Name: to.Ptr("AzureWebJobsStorage"), Value: &connStr},
			&armappservice.NameValuePair{Name: to.Ptr("WEBSITE_CONTENTAZUREFILECONNECTIONSTRING"), Value: &connStr},
			&armappservice.NameValuePair{Name: to.Ptr("WEBSITE_CONTENTSHARE"), Value: to.Ptr(name)})
		poller, err := webAppClient.BeginCreateOrUpdate(ctx,
			*state.ResourceGroup.Name,
			*targetFunctionApp.Name,
			*targetFunctionApp,
			nil)
		if err != nil {
			return err
		}
		resp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
		if err != nil {
			return err
		}
		state.FunctionApp[idx] = &resp.Site
	}
	return nil
}
