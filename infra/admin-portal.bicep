// Admin portal. Internal Container Apps environment, user-assigned identity, Key Vault.
// The config store is a private blob container. Shared keys are disabled.
// Container Apps cannot mount Azure Files with a managed identity
// (https://learn.microsoft.com/en-us/azure/container-apps/storage-mounts-azure-files),
// so this template does not create a file share and does not read a storage account key.
// One replica. Publish takes a lease and an ETag on active.json. Do not raise
// maxReplicas until that lease is the only writer. This file is not applied by CI.

targetScope = 'resourceGroup'

@description('HIPAA-eligible US region.')
@allowed([
  'eastus'
  'eastus2'
  'centralus'
  'northcentralus'
  'southcentralus'
  'westus'
  'westus2'
  'westus3'
  'westcentralus'
])
param location string = 'eastus'

param namePrefix string = 'prmadmin'

param entraTenantId string = 'f7812296-5bce-41dc-8102-b1b270e7c4c7'

@description('Portal app registration client id. Not a secret.')
param entraClientId string

param acrsValue string = 'c1'

param infraSubnetId string

param privateEndpointSubnetId string

param keyVaultDnsZoneId string

param blobDnsZoneId string

param containerImage string

param deployerPrincipalId string

@allowed([
  'User'
  'ServicePrincipal'
  'Group'
])
param deployerPrincipalType string = 'ServicePrincipal'

@secure()
param storeHmacKey string

@secure()
param auditHmacKey string

@secure()
param sessionHmacKey string

param publishToVnet bool = true

var secretsUserRole = '4633458b-17de-408a-b874-0445c86b69e6'
var secretsOfficerRole = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
var blobContributorRole = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id'
  location: location
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${namePrefix}kv${uniqueString(resourceGroup().id)}'
  location: location
  properties: {
    tenantId: entraTenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enablePurgeProtection: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}

resource storeSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'store-hmac-key'
  properties: {
    value: storeHmacKey
  }
}

resource auditSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'audit-hmac-key'
  properties: {
    value: auditHmacKey
  }
}

resource sessionSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'session-hmac-key'
  properties: {
    value: sessionHmacKey
  }
}

resource deployerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, deployerPrincipalId, secretsOfficerRole)
  scope: kv
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', secretsOfficerRole)
    principalId: deployerPrincipalId
    principalType: deployerPrincipalType
  }
}

resource identityRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, identity.id, secretsUserRole)
  scope: kv
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', secretsUserRole)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: '${namePrefix}${uniqueString(resourceGroup().id)}'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'None'
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storage
  name: 'default'
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'prm-config'
  properties: {
    publicAccess: 'None'
  }
}

resource blobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identity.id, blobContributorRole)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobContributorRole)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource blobEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${namePrefix}-blob-pe'
  location: location
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'blob'
        properties: {
          privateLinkServiceId: storage.id
          groupIds: [
            'blob'
          ]
        }
      }
    ]
  }
}

resource blobDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = {
  parent: blobEndpoint
  name: 'blob'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'blob'
        properties: {
          privateDnsZoneId: blobDnsZoneId
        }
      }
    ]
  }
}

resource kvEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${namePrefix}-kv-pe'
  location: location
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'vault'
        properties: {
          privateLinkServiceId: kv.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
}

resource kvDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = {
  parent: kvEndpoint
  name: 'vault'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'vault'
        properties: {
          privateDnsZoneId: keyVaultDnsZoneId
        }
      }
    ]
  }
}

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${namePrefix}-cae'
  location: location
  properties: {
    vnetConfiguration: {
      internal: true
      infrastructureSubnetId: infraSubnetId
    }
    appLogsConfiguration: {
      destination: 'azure-monitor'
    }
    zoneRedundant: false
  }
}

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${namePrefix}-app'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: publishToVnet
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
      }
      secrets: [
        {
          name: 'store-hmac-key'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/store-hmac-key'
          identity: identity.id
        }
        {
          name: 'audit-hmac-key'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/audit-hmac-key'
          identity: identity.id
        }
        {
          name: 'session-hmac-key'
          keyVaultUrl: '${kv.properties.vaultUri}secrets/session-hmac-key'
          identity: identity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'admin'
          image: containerImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            {
              name: 'PRM_ENV'
              value: 'production'
            }
            {
              name: 'PRM_ADMIN_BIND'
              value: '0.0.0.0'
            }
            {
              name: 'PRM_ADMIN_PORT'
              value: '8080'
            }
            {
              name: 'PRM_CONFIG_STORE'
              value: 'https://${storage.name}.blob.core.windows.net/prm-config'
            }
            {
              name: 'PRM_ADMIN_TENANT_ID'
              value: entraTenantId
            }
            {
              name: 'PRM_ADMIN_CLIENT_ID'
              value: entraClientId
            }
            {
              name: 'PRM_ADMIN_ACRS'
              value: acrsValue
            }
            {
              name: 'PRM_ADMIN_ASSERTION'
              value: 'managed_identity'
            }
            {
              name: 'PRM_ADMIN_MI_CLIENT_ID'
              value: identity.properties.clientId
            }
            {
              name: 'PRM_STORE_HMAC_KEY'
              secretRef: 'store-hmac-key'
            }
            {
              name: 'PRM_ADMIN_AUDIT_HMAC_KEY'
              secretRef: 'audit-hmac-key'
            }
            {
              name: 'PRM_ADMIN_SESSION_HMAC_KEY'
              secretRef: 'session-hmac-key'
            }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/healthz'
                port: 8080
              }
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/healthz'
                port: 8080
              }
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
  dependsOn: [
    storeSecret
    auditSecret
    sessionSecret
    identityRole
    container
    blobRole
  ]
}

output keyVaultName string = kv.name
output containerAppName string = app.name
output managedIdentityClientId string = identity.properties.clientId
// Federated credential on the portal app registration (created in Entra, not in this file):
// issuer https://login.microsoftonline.com/<tenant>/v2.0
// subject = managedIdentityPrincipalId
// audience api://AzureADTokenExchange
output managedIdentityPrincipalId string = identity.properties.principalId
output configStoreUrl string = 'https://${storage.name}.blob.core.windows.net/prm-config'
output environmentInternal bool = environment.properties.vnetConfiguration.internal
