# PCRv2-PoC

## Overview

The code in this repo was created to support a Proof Of Concept validating a target architecture of an application named PCR moving from IIS to Azure PaaS.

The main objectives the new architecture supports are:

- Completely isolate the processing pieces of the Application from external non-direct dependencies. We called it the "app runs in an island",

- Deploy a fully secured system in the island that is protected against external attacks,

- Deploy in an architecture where the Application can run, even if "external" services outages, like Active Directory Directory Services, on-premises systems, etc. happen,

- Provide this level of isolation, WITHOUT deploying a dedicated Application Service Environment v3. Just by leveraging a shared App Service with locking down features,

- Create a platform pattern that can be used for all Windows Server / IIS to Azure PaaS Development services migrations projects,

- Provide High-Availability, leveraging PaaS built-in features, and preparing for multi-region availability.

## Architecture diagram

![Architecture](img/PCR2_Isolated_AppSvc.png)

Notes:

- External Private endpoints in strong continuous lines are required system inputs:

  - Access to the Web portal via internal network,
  - Access for the external system to drop files to process,

- External Private endpoints in dashed lines are optional and for administrative purposes (they can be created, used, then deleted):
  - Access to the scm endpoint of the Function App, for app deployments,
  - Access to the scm endpoint of the Web App, for app deployments,
  - Access to the Azure SQL server management, for management.

## Repository content

The repository contains:

### Terraform code to deploy Azure resources

- an `azure/` folder with all the `terraform` files required to deploy the Azure resources/infrastructure:

  - `azure/pcr2-poc-resources/`: is the folder with the variables and main files for terraform. To run the terraform, a `<values whatever name>.auto.tfvars` file is required with the values set for these variables:

    ```
    # Terraform Service Principal
    tenant_id       = "" # <= Tenant Id of the tenant to deploy into
    subscription_id = "" # <= Subscription Id of the subscription to deploy into
    client_id       = "" # <= Terraform service principal Id to use by terraform azurerm provider
    client_secret   = "" # <= Terraform service principal secret to use by terraform azurerm provider

    # Prefixes for App Subscription
    main_region_code = "use2" # <= Region code to use. See /terraform/modules/base/locals.tf to select/add a code
    subsc_nickname   = "poc"  # <= Any nickname for the subscription
    subsc_adm_short  = "eb"   # <= Any other abbreviation

    # Access to External subscription
    external_snet_pe_id = "" <= The external subnet Id to connect the Island to through Private endpoints

    # SFTP User
    sftp_user_name = "" # <= The user name to connect to the external SFTP site
    sftp_user_pwd  = "" # <= The user password to connect to the external SFTP site

    # External facing Web App URL
    external_url  = "" # <= The FQDN for the Public/external facing endpoint of the Web portal
    tls_cert_path = "" # <= The local file path to the PFX (including private key) of the TLS certificate for the Web portal
    tls_cert_pwd  = "" # <= The password to open the PFX file
    ```

    > Important Note:
    > - The terraform plan is in 1 entire file, but can't be deployed in 1 run.
    > - There are some manual steps required before some resources can be deployed.
    > - It is suggested to comment all sections after a set of resources, deploy, then uncomment more resources, deploy, etc.
    > - The in-code notes/comments will help this process.

  - `azure/terraform-modules/`: is the folder with multiple re-used terraform modules by the `main_pcr2-poc.tf` file

    The modules are:
    - `base/`: this module enforces naming conventions for the resources,
    - `rg/`: Creates a Resource Group,
    - `pe/`: Creates 1 Private Endpoint,
    - `pe-dns/`: Creates eventual CNAME and A records for the Private Endpoints.

### .NET core solution with 2 projects

- a `src/` folder with:

  - `src/WebApp1/`:

    A Web Application with the following characteristics:
    - `.NET core 6.0 LTS`,
    - `no containers`,
    - `Razor Pages`,
    - `Microsoft.Data.SqlClient`,
    - `EntityFrameworkCore`,
    - `EntityFrameworkCore.SqlServer`,
    - `Microsoft.Identity.Web`,
    - `Azure.AI.AnomalyDetector`,
    - `Azure.Storage.Blobs`.

    It demonstrates the following technical patterns:
    - Azure `Storage Account Blobs/Containers` access and data manipulation through `Private endpoints` and `Managed Identity`,
    - `EntityFrameworkCore` access to `Azure SQL Server and database` through `Private endpoints` and `Managed Identity`,
    - Changing User Interface based on:
      - Database access availability,
      - Authenticated user or not (at logout),
    - Integration with `Application Service Authentication` provider to:
      - Allow access only to authenticated users with `Azure AD/Entra ID`,
      - Login is possible with on-premises credentials when on-premises link is down (requires Microsoft Entra Connect with [password hash synchronization](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/connect/whatis-phs),
      - Gather User token from `token store`,
    - Use of `Azure AI Anomaly Detector` from `Razor pages` using `.NET core` code to detect data anomalies (`Univariate` option),
    - `Publish` from `Visual Studio 2022` to the `Windows Web App` through `Private endpoints` with both `Web` and `Zip` deploy profiles.

  - `src/FunctionApp1/`:

    A Windows Function App with the following characteristics:
    - `.NET core 6.0 LTS`,
    - `no containers`,
    - All functions are `TimerTrigger` based,
    - `Microsoft.Data.SqlClient`,
    - `EntityFrameworkCore`,
    - `EntityFrameworkCore.SqlServer`,
    - `Azure.Storage.Blobs`,
    - `Microsoft.NET.Sdk.Functions`,
    - `WinSCP` (SFTP .NET client).

    Providing the following `Functions` demonstrating:
    - `WhatIsMyIP`:
      - This function uses an `httpClient` to query a service to get its Public Internet Address,
      - It logs the result which allows to check that all calls to the Public Internet from the `Function App` and the `Windows Web App` are done through the Azure `NAT Gateway` attached to the `App Service Integration VNet`,

    - `InputFilesProcessor`:
      - This function connects to a `Storage Account`, automatically leveraging the Function App `System Identity` and its assigned `RBAC role` on the storage account,
      - The `.NET` object manipulation is done with a `BlobContainerClient` then a `BlobItemClient`,
      - It reads the blob as a `binary` and process its content through a `MemStream()`,
      - From the data received, a new `blob item` is generated then stored in another `Storage Account`,also accessed through `Managed Identity`,
      - The code uses a `Stream` object to demonstrate a wide scenario. In code is the reference to deal with `TXT` files.
      - The `input => processing => output` of content is fully done in memory. No access to the [`Physical File Provider`](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/file-providers?view=aspnetcore-6.0) trough `System.IO.File` is done.

    - `QueryDatabase`:
      - Demonstrates the Dependency Injection of an `EntityFrameworkCore DbContext` in a Function App,
      - It requires the `Startup.cs` class, that overrides the `FunctionStartup` default,
      - It gives access to the `DbContext` in the function class,
      - The "Default" integration between `Function App` and `SQL Server` is done through `inbound` and `output` bindings. These bindings are designed to respectively react to a SQL Server event (inbound) or store data to SQL Server, like creating a new row (outbound). The code provided here demonstrates how to manipulate the entire Database, like querying entities,
      - In that function, the database is accessed via `Managed Identity`, queried for its `Students` entities, then outputs to the log the students' names.

    - `SftpClient`:
      - Demonstrates how to use WinSCP SFTP NuGet package to connect to and query a SFTP server on the Public Internet,
      - It connects, list the files in the home directory and outputs some of their properties in the log.

## Architectural notes

There are few considerations to understand in this architecture:

1. The "Application island" is completely independent to/from any other networks,

2. 2 VNets are used:
    1. one for the Application Service, Function App and Private endpoints,
    2. one dedicated to the Application Gateway,

    This is because the deployment of the Application Gateway on the App Service VNet was almost always ending with a `Failed` Application Gateway.
    With a dedicated VNet, control on the Application Gateway deployment is gained, and it can be used as a commodity (replaced, disconnected).

    The VNet peering between the 2 VNets configuration is:
    - Application Gateway VNet => Application Service VNet: only `"Allow access to remote virtual network"`,
    - Application Service VNet => Application Gateway VNet: `"Allow access to remote virtual network"` + `"Allow traffic to remote virtual network"`.

3. The connectivity to `Log Analytics Workspace` and `Application Insights` is done within the Azure network, but not through Private endpoints / Private Link. This can be done with [Azure Monitor Private Link Service (AMPLS)](https://learn.microsoft.com/en-us/samples/azure-samples/azure-monitor-private-link-scope/azure-monitor-private-link-scope/), which is not in this scope,

4. The `AI Cognitive Services Anomaly Detector` is connected through a Private endpoint.
