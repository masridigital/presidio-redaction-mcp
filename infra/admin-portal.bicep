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

@description('Digest-pinned admin image. A floating tag is not accepted.')
param containerImage string

@description('Proxy managed identity principal id. Verify-only on the signing key, and the only writer of the version floor.')
param proxyPrincipalId string

param deployerPrincipalId string

@allowed([
  'User'
  'ServicePrincipal'
  'Group'
])
param deployerPrincipalType string = 'ServicePrincipal'

param publishToVnet bool = true

// Deploy fails unless containerImage is repository@sha256:<digest>.
var adminImagePin = indexOf(containerImage, '@sha256:') >= 0 && indexOf(containerImage, ':latest') < 0 ? 'pinned' : substring(containerImage, length(containerImage), 1)

var secretsOfficerRole = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
var cryptoOfficerRole = '14b46e9e-c2b7-41b4-b545-8d5e335c5e6a'
var blobContributorRole = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var blobReaderRole = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'

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

resource signingKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: kv
  name: 'prm-config-signing'
  properties: {
    kty: 'RSA'
    keySize: 2048
    keyOps: [
      'sign'
      'verify'
    ]
    attributes: {
      enabled: true
    }
  }
  dependsOn: [
    deployerCryptoRole
  ]
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

resource deployerCryptoRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, deployerPrincipalId, cryptoOfficerRole)
  scope: kv
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', cryptoOfficerRole)
    principalId: deployerPrincipalId
    principalType: deployerPrincipalType
  }
}

resource signRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'prm-config-sign')
  properties: {
    roleName: 'prm-config-sign-${uniqueString(resourceGroup().id)}'
    description: 'Sign the config key and create the session secret. Generated in Key Vault.'
    type: 'CustomRole'
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.KeyVault/vaults/keys/read'
          'Microsoft.KeyVault/vaults/keys/sign/action'
          'Microsoft.KeyVault/vaults/secrets/getSecret/action'
          'Microsoft.KeyVault/vaults/secrets/setSecret/action'
        ]
        notDataActions: []
      }
    ]
    assignableScopes: [
      resourceGroup().id
    ]
  }
}

resource verifyRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'prm-config-verify')
  properties: {
    roleName: 'prm-config-verify-${uniqueString(resourceGroup().id)}'
    description: 'Read and verify the config signing key. Sign is not included.'
    type: 'CustomRole'
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.KeyVault/vaults/keys/read'
          'Microsoft.KeyVault/vaults/keys/verify/action'
        ]
        notDataActions: []
      }
    ]
    assignableScopes: [
      resourceGroup().id
    ]
  }
}

resource identitySign 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, identity.id, 'sign')
  scope: kv
  properties: {
    roleDefinitionId: signRole.id
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource proxyVerify 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, proxyPrincipalId, 'verify')
  scope: kv
  properties: {
    roleDefinitionId: verifyRole.id
    principalId: proxyPrincipalId
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
  properties: {
    isVersioningEnabled: true
    deleteRetentionPolicy: {
      enabled: true
      days: 30
    }
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'prm-config'
  properties: {
    publicAccess: 'None'
  }
}

resource configImmutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-01-01' = {
  parent: container
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: 365
    allowProtectedAppendWrites: false
  }
}

resource floorContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'prm-floor'
  properties: {
    publicAccess: 'None'
  }
}

resource floorImmutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-01-01' = {
  parent: floorContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: 365
    allowProtectedAppendWrites: true
  }
}

resource blobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(container.id, identity.id, blobContributorRole)
  scope: container
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobContributorRole)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource floorWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(floorContainer.id, proxyPrincipalId, blobContributorRole)
  scope: floorContainer
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobContributorRole)
    principalId: proxyPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource proxyConfigReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(container.id, proxyPrincipalId, blobReaderRole)
  scope: container
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobReaderRole)
    principalId: proxyPrincipalId
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
  tags: {
    imagePin: adminImagePin
  }
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
              name: 'PRM_SIGNING_KEY_URL'
              value: '${kv.properties.vaultUri}keys/prm-config-signing'
            }
            {
              name: 'PRM_KEY_VAULT_URL'
              value: kv.properties.vaultUri
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
    signingKey
    identitySign
    container
    configImmutability
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
output signingKeyUrl string = '${kv.properties.vaultUri}keys/prm-config-signing'
output versionFloorUrl string = 'https://${storage.name}.blob.core.windows.net/prm-floor'
output environmentInternal bool = environment.properties.vnetConfiguration.internal
