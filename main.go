package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	"github.com/goccy/go-yaml"
	"github.com/google/uuid"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type SDKClient struct {
	resourceGroupClient      *armresources.ResourceGroupsClient
	accountStorageClient     *armstorage.AccountsClient
	planClient               *armappservice.PlansClient
	webAppClient             *armappservice.WebAppsClient //functions, web apps for container
	deploymentClient         *armresources.DeploymentsClient
	managedEnvironmentClient *armappcontainers.ManagedEnvironmentsClient //container app
	managedClusterClient     *armcontainerservice.ManagedClustersClient  //aks
	containerGroupClient     *armcontainerinstance.ContainerGroupsClient //aci
	containerAppClient       *armappcontainers.ContainerAppsClient
	blobClient               *azblob.Client
}

var (
	client                = SDKClient{}
	subscriptionID        = "df8d5581-0d42-4976-9084-fd258cb1d437"
	resourceGroupTemplate = &armresources.ResourceGroup{
		Location: to.Ptr("eastus"),
		Name:     to.Ptr("testpipecdrg"),
	}
	storageAccountName = "testpipecdsa"
	storageTemplate    = &armstorage.AccountCreateParameters{
		Location: to.Ptr("eastus"),
		Kind:     to.Ptr(armstorage.KindStorageV2),
		SKU: &armstorage.SKU{
			Name: to.Ptr(armstorage.SKUNameStandardLRS),
		},
		Properties: &armstorage.AccountPropertiesCreateParameters{
			AccessTier:        to.Ptr(armstorage.AccessTierCool),
			MinimumTLSVersion: to.Ptr(armstorage.MinimumTLSVersionTLS12),
		},
	}
	linuxConsumptionPlanTemplate = &armappservice.Plan{
		Location: to.Ptr("eastus"),
		Name:     to.Ptr("testpipecdlinuxconsumptionplan"),
		Kind:     to.Ptr("functionapp"),
		SKU: &armappservice.SKUDescription{
			Name: to.Ptr("Y1"),
			Tier: to.Ptr("Dynamic"),
		},
	}
	windowConsumptionPlanTemplate = &armappservice.Plan{
		Location: to.Ptr("eastus"),
		Name:     to.Ptr("testpipecdwindowconsumptionplan"),
		Kind:     to.Ptr("functionapp"),
		SKU: &armappservice.SKUDescription{
			Name: to.Ptr("Y1"),
			Tier: to.Ptr("Dynamic"),
		},
	}
	goRuntimeFunctionTemplate = &armappservice.Site{
		Location: to.Ptr("eastus"),
		Name:     to.Ptr("testpipecdgoruntime"),
		Kind:     to.Ptr("functionapp,linux"),
		Properties: &armappservice.SiteProperties{
			Reserved: to.Ptr(true),
			SiteConfig: &armappservice.SiteConfig{
				LinuxFxVersion: to.Ptr(""),
				AppSettings: []*armappservice.NameValuePair{
					{Name: to.Ptr("FUNCTIONS_WORKER_RUNTIME"), Value: to.Ptr("custom")},
					{Name: to.Ptr("FUNCTIONS_EXTENSION_VERSION"), Value: to.Ptr("~4")},
					//AzureWebJobsStorage
				},
			},
			//ServerFarmID: to.Ptr(),for non consumption plan
		},
	}
	csRuntimeFunctionTemplate = &armappservice.Site{
		Name:     to.Ptr("testpipecdcsruntime"),
		Location: to.Ptr("eastus"),
		Kind:     to.Ptr("functionapp"),
		Properties: &armappservice.SiteProperties{
			SiteConfig: &armappservice.SiteConfig{
				NetFrameworkVersion: to.Ptr("v8.0"),
				AppSettings: []*armappservice.NameValuePair{
					{Name: to.Ptr("WEBSITE_USE_PLACEHOLDER_DOTNETISOLATED"), Value: to.Ptr("1")},
					{Name: to.Ptr("FUNCTIONS_WORKER_RUNTIME"), Value: to.Ptr("dotnet-isolated")},
					{Name: to.Ptr("FUNCTIONS_EXTENSION_VERSION"), Value: to.Ptr("~4")},
					//https://learn.microsoft.com/en-us/azure/azure-functions/functions-recover-storage-account#guidance
					//AzureWebJobsStorage
					//WEBSITE_CONTENTAZUREFILECONNECTIONSTRING
					//WEBSITE_CONTENTSHARE
				},
			},
		},
	}
	csDirectory       = "~/azure/azd/http/bin/publish"
	goDirectory       = "~/azure/temp"
	csSlot            = "test"
	blobContainerName = "function-releases"
)
var (
	cred                  azcore.TokenCredential
	resourceGroup         *armresources.ResourceGroup
	storageAccount        *armstorage.Account
	linuxConsumptionPlan  *armappservice.Plan
	windowConsumptionPlan *armappservice.Plan
	goRuntimeFunction     *armappservice.Site
	goRuntimeFunctionSlot *armappservice.Site
	csRuntimeFunction     *armappservice.Site
	csRuntimeFunctionSlot *armappservice.Site
)

type lang string

var (
	golang    lang = "go"
	dotnet    lang = "dotnet"
	golangStr      = string(golang)
	dotnetStr      = string(dotnet)
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Panic(err)
	}
}

func run(ctx context.Context) error {
	var err error
	if err = initializeClient(); err != nil {
		return err
	}
	if err = ensureResourceGroup(ctx); err != nil {
		return err
	}
	if err = ensureStorageAccount(ctx); err != nil {
		return err
	}
	//if err = ensureAppServicePlan(ctx); err != nil {
	//	return err
	//}
	if err = ensureFunctionApp(ctx); err != nil {
		return err
	}
	//if err = kuduZipDeploy(ctx, *csRuntimeFunction.Name, "test", csDirectory, dotnet); err != nil {
	//	return err
	//}
	if err = blobZipDeploy(ctx, *resourceGroup.Name, *goRuntimeFunction.Name, "", goDirectory, golang); err != nil {
		return err
	}
	return nil
}
func initializeClient() error {
	var err error
	cred, err = azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return err
	}
	if client.resourceGroupClient, err = armresources.NewResourceGroupsClient(subscriptionID, cred, nil); err != nil {
		return err
	}
	if client.accountStorageClient, err = armstorage.NewAccountsClient(subscriptionID, cred, nil); err != nil {
		return err
	}
	if client.planClient, err = armappservice.NewPlansClient(subscriptionID, cred, nil); err != nil {
		return err
	}
	if client.webAppClient, err = armappservice.NewWebAppsClient(subscriptionID, cred, nil); err != nil {
		return err
	}
	if client.deploymentClient, err = armresources.NewDeploymentsClient(subscriptionID, cred, nil); err != nil {
		return err
	}
	if client.managedEnvironmentClient, err = armappcontainers.NewManagedEnvironmentsClient(subscriptionID, cred, nil); err != nil {
		return err
	}
	if client.managedClusterClient, err = armcontainerservice.NewManagedClustersClient(subscriptionID, cred, nil); err != nil {
		return err
	}
	if client.containerGroupClient, err = armcontainerinstance.NewContainerGroupsClient(subscriptionID, cred, nil); err != nil {
		return err
	}
	if client.containerAppClient, err = armappcontainers.NewContainerAppsClient(subscriptionID, cred, nil); err != nil {
		return err
	}
	return nil
}
func dump(T any) error {
	bytes, err := yaml.Marshal(T)
	if err != nil {
		return err
	}
	println(string(bytes))
	return nil
}
func ensureResourceGroup(ctx context.Context) error {
	resp, err := client.resourceGroupClient.Get(ctx, *resourceGroupTemplate.Name, nil)
	var notFound *azcore.ResponseError
	if err != nil {
		if errors.As(err, &notFound) && notFound.StatusCode == http.StatusNotFound {
			resp, err := client.resourceGroupClient.CreateOrUpdate(
				ctx,
				*resourceGroupTemplate.Name,
				*resourceGroupTemplate,
				nil)
			if err != nil {
				return err
			}
			resourceGroup = &resp.ResourceGroup
			return nil
		} else {
			return err
		}
	} else {
		resourceGroup = &resp.ResourceGroup
		return dump(*resourceGroup)
	}
}

func ensureStorageAccount(ctx context.Context) error {
	resp, err := client.accountStorageClient.GetProperties(ctx, *resourceGroup.Name, storageAccountName, nil)
	if err != nil {
		var notFound *azcore.ResponseError
		if errors.As(err, &notFound) && notFound.StatusCode == http.StatusNotFound {
			pollerResp, err := client.accountStorageClient.BeginCreate(
				ctx,
				*resourceGroup.Name,
				storageAccountName,
				*storageTemplate, nil)
			if err != nil {
				return err
			}
			resp, err := pollerResp.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
			if err != nil {
				return err
			}
			storageAccount = &resp.Account
			return nil
		} else {
			return err
		}
	} else {
		storageAccount = &resp.Account
		return dump(*storageAccount)
	}
}

func ensureAppServicePlan(ctx context.Context) error {
	resp, err := client.planClient.Get(ctx, *resourceGroup.Name, *linuxConsumptionPlanTemplate.Name, nil)
	var notFound *azcore.ResponseError
	if err != nil {
		if errors.As(err, &notFound) && notFound.StatusCode == http.StatusNotFound {
			poller, err := client.planClient.BeginCreateOrUpdate(
				ctx,
				*resourceGroup.Name,
				*linuxConsumptionPlanTemplate.Name,
				*linuxConsumptionPlanTemplate,
				nil)
			if err != nil {
				return err
			}
			resp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
			if err != nil {
				return err
			}
			linuxConsumptionPlan = &resp.Plan
			return nil
		} else {
			return err
		}
	} else {
		linuxConsumptionPlan = &resp.Plan
		err = dump(*linuxConsumptionPlan)
		if err != nil {
			return err
		}
	}
	resp, err = client.planClient.Get(ctx, *resourceGroup.Name, *windowConsumptionPlanTemplate.Name, nil)
	if err != nil {
		if errors.As(err, &notFound) && notFound.StatusCode == http.StatusNotFound {
			poller, err := client.planClient.BeginCreateOrUpdate(ctx, *resourceGroup.Name, *windowConsumptionPlanTemplate.Name, *windowConsumptionPlanTemplate, nil)
			if err != nil {
				return err
			}
			resp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
			if err != nil {
				return err
			}
			windowConsumptionPlan = &resp.Plan
			return nil
		} else {
			return err
		}
	} else {
		windowConsumptionPlan = &resp.Plan
		err = dump(*windowConsumptionPlan)
		if err != nil {
			return err
		}
	}
	return nil
}

func getStorageAccountKey(ctx context.Context) (string, error) {
	keyResp, err := client.accountStorageClient.ListKeys(ctx,
		*resourceGroup.Name,
		*storageAccount.Name,
		nil)
	if err != nil {
		return "", err
	}
	return *keyResp.Keys[0].Value, nil
}

func ensureFunctionApp(ctx context.Context) error {
	key, err := getStorageAccountKey(ctx)
	if err != nil {
		return err
	}
	jobStorage := fmt.Sprintf("DefaultEndpointsProtocol=https;EndpointSuffix=core.windows.net;AccountName=%s;AccountKey=%s", storageAccountName, key)
	fshare := storageAccountName + uuid.New().String()
	if len(fshare) > 60 {
		fshare = fshare[:60]
	}
	goRuntimeFunctionTemplate.Properties.SiteConfig.AppSettings = append(goRuntimeFunctionTemplate.Properties.SiteConfig.AppSettings,
		&armappservice.NameValuePair{Name: to.Ptr("AzureWebJobsStorage"), Value: &jobStorage})
	csRuntimeFunctionTemplate.Properties.SiteConfig.AppSettings = append(csRuntimeFunctionTemplate.Properties.SiteConfig.AppSettings,
		&armappservice.NameValuePair{Name: to.Ptr("AzureWebJobsStorage"), Value: &jobStorage},
		&armappservice.NameValuePair{Name: to.Ptr("WEBSITE_CONTENTAZUREFILECONNECTIONSTRING"), Value: &jobStorage},
		&armappservice.NameValuePair{Name: to.Ptr("WEBSITE_CONTENTSHARE"), Value: &fshare},
	)
	{
		goResp, err := client.webAppClient.Get(ctx, *resourceGroup.Name, *goRuntimeFunctionTemplate.Name, nil)
		if err != nil {
			var notFound *azcore.ResponseError
			if errors.As(err, &notFound) && notFound.StatusCode == http.StatusNotFound {
				poller, err := client.webAppClient.BeginCreateOrUpdate(
					ctx, *resourceGroup.Name,
					*goRuntimeFunctionTemplate.Name,
					*goRuntimeFunctionTemplate,
					nil)
				if err != nil {
					return err
				}
				resp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
				if err != nil {
					return err
				}
				goRuntimeFunction = &resp.Site
				return nil
			} else {
				return err
			}
		} else {
			goRuntimeFunction = &goResp.Site
			err = dump(*goRuntimeFunction)
			if err != nil {
				return err
			}
		}
	}
	{
		csResp, err := client.webAppClient.Get(ctx, *resourceGroup.Name, *csRuntimeFunctionTemplate.Name, nil)
		if err != nil {
			var notFound *azcore.ResponseError
			if errors.As(err, &notFound) && notFound.StatusCode == http.StatusNotFound {
				poller, err := client.webAppClient.BeginCreateOrUpdate(
					ctx, *resourceGroup.Name,
					*csRuntimeFunctionTemplate.Name,
					*csRuntimeFunctionTemplate,
					nil)
				if err != nil {
					return err
				}
				resp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
				if err != nil {
					return err
				}
				csRuntimeFunction = &resp.Site
				return nil
			} else {
				return err
			}
		} else {
			csRuntimeFunction = &csResp.Site
			err = dump(*csRuntimeFunction)
			if err != nil {
				return err
			}
		}
	}
	{
		csRuntimeFunctionTemplate.Name = nil
		sresp, err := client.webAppClient.GetSlot(ctx, *resourceGroup.Name, *csRuntimeFunction.Name, csSlot, nil)
		needCreate := false
		if err != nil {
			var notFound *azcore.ResponseError
			if errors.As(err, &notFound) && notFound.StatusCode == http.StatusNotFound {
				needCreate = true
			} else {
				return err
			}
		}
		if sresp.Site.ID == nil {
			needCreate = true
		}
		if needCreate {
			poller, err := client.webAppClient.BeginCreateOrUpdateSlot(
				ctx, *resourceGroup.Name,
				*csRuntimeFunction.Name,
				csSlot,
				*csRuntimeFunctionTemplate,
				nil)
			if err != nil {
				return err
			}
			resp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
			if err != nil {
				return err
			}
			csRuntimeFunctionSlot = &resp.Site
			return nil
		} else {
			csRuntimeFunctionSlot = &sresp.Site
			err = dump(*csRuntimeFunctionSlot)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func createZipFromFolder(sourceDir string, lang lang) (*os.File, error) {
	cleanup := false
	absSrc, err := filepath.Abs(sourceDir)
	if err != nil {
		return nil, err
	}

	tempFile, err := os.CreateTemp("", "pipecd-azure-deploy-*.zip")
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanup {
			_ = tempFile.Close()
			_ = os.Remove(tempFile.Name())
		}
	}()
	w := zip.NewWriter(tempFile)
	defer w.Close()

	err = filepath.Walk(sourceDir, func(path string, fi fs.FileInfo, errWalk error) error {
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(fi)
		if err != nil {
			return err
		}
		header.Name, err = filepath.Rel(absSrc, path)
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		} else {
			header.Method = zip.Deflate

		}

		fw, err := w.CreateHeader(header)

		if err != nil {
			return err
		}
		//if fi.IsDir() {
		//	return nil
		//}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(fw, file)
		return err
	})
	if err != nil {
		cleanup = true
		return nil, err
	}
	return tempFile, nil
}
func kuduZipDeploy(ctx context.Context, functionName, slotName, srcDir string, lang lang) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	srcDir = strings.ReplaceAll(srcDir, "~", home)
	file, err := createZipFromFolder(srcDir, lang)
	if err != nil {
		return err
	}
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	httpClient := &http.Client{}
	var publishCreds *armappservice.UserProperties
	if slotName == "" {
		poller, err := client.webAppClient.BeginListPublishingCredentials(ctx, *resourceGroup.Name, functionName, nil)
		if err != nil {
			return err
		}
		credResp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
		if err != nil {
			return err
		}
		publishCreds = credResp.User.Properties
	} else {
		poller, err := client.webAppClient.BeginListPublishingCredentialsSlot(ctx, *resourceGroup.Name, functionName, slotName, nil)
		if err != nil {
			return err
		}
		credResp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
		if err != nil {
			return err
		}
		publishCreds = credResp.User.Properties
	}
	deployReq, err := http.NewRequest("POST", *publishCreds.ScmURI+"/api/zipdeploy", file)
	if err != nil {
		return err
	}
	queryParams := deployReq.URL.Query()
	queryParams.Set("isAsync", "true")
	queryParams.Set("Deployer", "pipecd")
	deployReq.URL.RawQuery = queryParams.Encode()
	deployReq.Header.Set("Content-Type", "application/octet-stream")
	deployReq.Header.Set("Cache-Control", "no-cache")
	var token string
	var csmAllow bool
	if slotName == "" {
		auth, err := client.webAppClient.GetScmAllowed(ctx, *resourceGroup.Name, functionName, nil)
		if err != nil {
			return err
		}
		csmAllow = *auth.CsmPublishingCredentialsPoliciesEntity.Properties.Allow
	} else {
		auth, err := client.webAppClient.GetScmAllowedSlot(ctx, *resourceGroup.Name, functionName, slotName, nil)
		if err != nil {
			return err
		}
		csmAllow = *auth.CsmPublishingCredentialsPoliciesEntity.Properties.Allow
	}
	if !csmAllow {
		resp, err := cred.GetToken(ctx, policy.TokenRequestOptions{
			Scopes: []string{
				"https://management.core.windows.net/.default",
			},
		})
		if err != nil {
			return err
		}
		token = resp.Token
		deployReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}
	deployResp, err := httpClient.Do(deployReq)
	if err != nil {
		return err
	}
	defer deployResp.Body.Close()
	if deployResp.StatusCode != http.StatusAccepted {
		body, err := io.ReadAll(deployResp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("zip deployment with status code %d: %s", deployResp.StatusCode, string(body))
	}
	setCookie := deployResp.Cookies()
	_ = dump(*deployResp)
	pollLink := deployResp.Header.Get("Location")
	if pollLink == "" {
		return fmt.Errorf("zip deployment with status code %d: no location header found", deployResp.StatusCode)
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
progressLoop:
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("zip deployment timed out")
		case <-ticker.C:
			progressReq, err := http.NewRequest("GET", pollLink, nil)
			for _, cookie := range setCookie {
				progressReq.AddCookie(cookie)
			}
			if !csmAllow {
				resp, err := cred.GetToken(ctx, policy.TokenRequestOptions{
					Scopes: []string{
						"https://management.core.windows.net/.default",
					},
				})
				if err != nil {
					return err
				}
				token = resp.Token
				deployReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			} else {
				progressReq.SetBasicAuth(*publishCreds.PublishingUserName, *publishCreds.PublishingPassword)
			}
			progressResp, err := httpClient.Do(progressReq)
			if err != nil {
				return err
			}
			body, err := io.ReadAll(progressResp.Body)
			progressResp.Body.Close()
			if err != nil {
				return err
			}
			if progressResp.StatusCode != http.StatusOK && progressResp.StatusCode != http.StatusAccepted {
				return fmt.Errorf("zip deployment status check failed with status code %d, body %s", progressResp.StatusCode, string(body))
			}
			var f struct {
				Status int `json:"status"`
			}
			if err = json.Unmarshal(body, &f); err != nil {
				return err
			}
			if f.Status == 3 {
				return fmt.Errorf("zip deployment failed")
			}
			if f.Status == 4 {
				break progressLoop
			}
		}
	}
	var respErr *azcore.ResponseError
	if slotName == "" {
		_, err = client.webAppClient.SyncFunctions(ctx, *resourceGroup.Name, functionName, nil)
		if err != nil && errors.As(err, &respErr) && respErr.StatusCode == http.StatusOK {
			return nil
		}
		return err
	} else {
		_, err = client.webAppClient.SyncFunctionsSlot(ctx, *resourceGroup.Name, functionName, slotName, nil)
		if err != nil && errors.As(err, &respErr) && respErr.StatusCode == http.StatusOK {
			return nil
		}
		return err
	}
}

func blobZipDeploy(ctx context.Context, resourceGroupName, functionName, slotName, srcDir string, lang lang) error {
	var prop map[string]*string
	if slotName == "" {
		resp, err := client.webAppClient.ListApplicationSettings(ctx, resourceGroupName, functionName, nil)
		if err != nil {
			return err
		}
		prop = resp.Properties
	} else {
		resp, err := client.webAppClient.ListApplicationSettingsSlot(ctx, resourceGroupName, functionName, slotName, nil)
		if err != nil {
			return err
		}
		prop = resp.Properties
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	srcDir = strings.ReplaceAll(srcDir, "~", home)
	file, err := createZipFromFolder(srcDir, lang)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	blobName := fmt.Sprintf("%s-%s.zip", time.Now().UTC().Format("20060102150405"), uuid.New())
	key, err := getStorageAccountKey(ctx)
	if err != nil {
		return err
	}
	sharedKey, err := azblob.NewSharedKeyCredential(storageAccountName, key)
	if err != nil {
		return err
	}
	client.blobClient, err = azblob.NewClientWithSharedKeyCredential(fmt.Sprintf("https://%s.blob.core.windows.net/", storageAccountName), sharedKey, nil)
	if err != nil {
		return err
	}
	_, err = client.blobClient.UploadFile(ctx, blobContainerName, blobName, file, &azblob.UploadFileOptions{
		AccessTier: to.Ptr(blob.AccessTierCool),
	})
	if err != nil {
		return err
	}
	sasURLParams, err := sas.BlobSignatureValues{
		Version:       "2018-03-28",
		ExpiryTime:    time.Now().UTC().Add(24 * 7 * 520 * time.Hour),
		ContainerName: blobContainerName,
		BlobName:      blobName,
		Permissions:   (&sas.BlobPermissions{Read: true}).String(),
	}.SignWithSharedKey(sharedKey)
	if err != nil {
		return err
	}
	print(sasURLParams.Encode())
	var respErr *azcore.ResponseError

	//prop["ENABLE_ORYX_BUILD"] = to.Ptr("true")
	//prop["SCM_DO_BUILD_DURING_DEPLOYMENT"] = to.Ptr("true")
	prop["WEBSITE_MOUNT_ENABLED"] = to.Ptr("1")
	prop["WEBSITE_RUN_FROM_PACKAGE"] = to.Ptr(fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s?%s", storageAccountName, blobContainerName, blobName, sasURLParams.Encode()))
	if slotName == "" {
		_, err = client.webAppClient.UpdateApplicationSettings(ctx, resourceGroupName, functionName, armappservice.StringDictionary{
			Properties: prop,
		}, nil)
		if err != nil {
			return err
		}
		for attempt := 1; attempt <= 3; attempt++ {
			_, err = client.webAppClient.SyncFunctions(ctx, *resourceGroup.Name, functionName, nil)
			if err == nil {
				break
			}
			if errors.As(err, &respErr) {
				if respErr.StatusCode == http.StatusOK {
					return nil
				}
				if respErr.StatusCode == http.StatusBadRequest {
					time.Sleep(time.Duration(attempt) * time.Second)
					continue
				}
				return err
			} else {
				return err
			}
		}

		return err
	} else {
		_, err = client.webAppClient.UpdateApplicationSettingsSlot(ctx, resourceGroupName, functionName, slotName, armappservice.StringDictionary{
			Properties: prop,
		}, nil)
		if err != nil {
			return err
		}
		_, err = client.webAppClient.SyncFunctionsSlot(ctx, *resourceGroup.Name, functionName, slotName, nil)
		if err != nil && errors.As(err, &respErr) && respErr.StatusCode == http.StatusOK {
			return nil
		}
		return err
	}
	//	httpClient := &http.Client{}
	//	var publishCreds *armappservice.UserProperties
	//	if slotName == "" {
	//		poller, err := client.webAppClient.BeginListPublishingCredentials(ctx, *resourceGroup.Name, functionName, nil)
	//		if err != nil {
	//			return err
	//		}
	//		credResp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
	//		if err != nil {
	//			return err
	//		}
	//		publishCreds = credResp.User.Properties
	//	} else {
	//		poller, err := client.webAppClient.BeginListPublishingCredentialsSlot(ctx, *resourceGroup.Name, functionName, slotName, nil)
	//		if err != nil {
	//			return err
	//		}
	//		credResp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{Frequency: 5 * time.Second})
	//		if err != nil {
	//			return err
	//		}
	//		publishCreds = credResp.User.Properties
	//	}
	//	deployReq, err := http.NewRequest("POST", *publishCreds.ScmURI+"/api/zipdeploy", file)
	//	if err != nil {
	//		return err
	//	}
	//	queryParams := deployReq.URL.Query()
	//	queryParams.Set("isAsync", "true")
	//	queryParams.Set("Deployer", "pipecd")
	//	deployReq.URL.RawQuery = queryParams.Encode()
	//	deployReq.Header.Set("Content-Type", "application/octet-stream")
	//	deployReq.Header.Set("Cache-Control", "no-cache")
	//	var token string
	//	var csmAllow bool
	//	if slotName == "" {
	//		auth, err := client.webAppClient.GetScmAllowed(ctx, *resourceGroup.Name, functionName, nil)
	//		if err != nil {
	//			return err
	//		}
	//		csmAllow = *auth.CsmPublishingCredentialsPoliciesEntity.Properties.Allow
	//	} else {
	//		auth, err := client.webAppClient.GetScmAllowedSlot(ctx, *resourceGroup.Name, functionName, slotName, nil)
	//		if err != nil {
	//			return err
	//		}
	//		csmAllow = *auth.CsmPublishingCredentialsPoliciesEntity.Properties.Allow
	//	}
	//	if !csmAllow {
	//		resp, err := cred.GetToken(ctx, policy.TokenRequestOptions{
	//			Scopes: []string{
	//				"https://management.core.windows.net/.default",
	//			},
	//		})
	//		if err != nil {
	//			return err
	//		}
	//		token = resp.Token
	//		deployReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	//	}
	//	deployResp, err := httpClient.Do(deployReq)
	//	if err != nil {
	//		return err
	//	}
	//	defer deployResp.Body.Close()
	//	if deployResp.StatusCode != http.StatusAccepted {
	//		body, err := io.ReadAll(deployResp.Body)
	//		if err != nil {
	//			return err
	//		}
	//		return fmt.Errorf("zip deployment with status code %d: %s", deployResp.StatusCode, string(body))
	//	}
	//	setCookie := deployResp.Cookies()
	//	_ = dump(*deployResp)
	//	pollLink := deployResp.Header.Get("Location")
	//	if pollLink == "" {
	//		return fmt.Errorf("zip deployment with status code %d: no location header found", deployResp.StatusCode)
	//	}
	//	ticker := time.NewTicker(5 * time.Second)
	//	defer ticker.Stop()
	//progressLoop:
	//	for {
	//		select {
	//		case <-ctx.Done():
	//			return fmt.Errorf("zip deployment timed out")
	//		case <-ticker.C:
	//			progressReq, err := http.NewRequest("GET", pollLink, nil)
	//			for _, cookie := range setCookie {
	//				progressReq.AddCookie(cookie)
	//			}
	//			if !csmAllow {
	//				resp, err := cred.GetToken(ctx, policy.TokenRequestOptions{
	//					Scopes: []string{
	//						"https://management.core.windows.net/.default",
	//					},
	//				})
	//				if err != nil {
	//					return err
	//				}
	//				token = resp.Token
	//				deployReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	//			} else {
	//				progressReq.SetBasicAuth(*publishCreds.PublishingUserName, *publishCreds.PublishingPassword)
	//			}
	//			progressResp, err := httpClient.Do(progressReq)
	//			if err != nil {
	//				return err
	//			}
	//			body, err := io.ReadAll(progressResp.Body)
	//			progressResp.Body.Close()
	//			if err != nil {
	//				return err
	//			}
	//			if progressResp.StatusCode != http.StatusOK && progressResp.StatusCode != http.StatusAccepted {
	//				return fmt.Errorf("zip deployment status check failed with status code %d, body %s", progressResp.StatusCode, string(body))
	//			}
	//			var f struct {
	//				Status int `json:"status"`
	//			}
	//			if err = json.Unmarshal(body, &f); err != nil {
	//				return err
	//			}
	//			if f.Status == 3 {
	//				return fmt.Errorf("zip deployment failed")
	//			}
	//			if f.Status == 4 {
	//				break progressLoop
	//			}
	//		}
	//	}
	//	//var respErr *azcore.ResponseError
	//	if slotName == "" {
	//		_, err = client.webAppClient.SyncFunctions(ctx, *resourceGroup.Name, functionName, nil)
	//		if err != nil && errors.As(err, &respErr) && respErr.StatusCode == http.StatusOK {
	//			return nil
	//		}
	//		return err
	//	} else {
	//		_, err = client.webAppClient.SyncFunctionsSlot(ctx, *resourceGroup.Name, functionName, slotName, nil)
	//		if err != nil && errors.As(err, &respErr) && respErr.StatusCode == http.StatusOK {
	//			return nil
	//		}
	//		return err
	//	}
}
