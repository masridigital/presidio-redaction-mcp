// Primary deploy: Azure Container Apps, Key Vault, private networking, API Management.
// HIPAA-eligible US region. No secret values. The container re-validates Entra JWTs.
// PHI ingress is private. This file is not applied by CI.

targetScope = 'resourceGroup'

@description('HIPAA-eligible US region.')
param location string = 'eastus'

@description('Pinned Entra tenant. common, organizations, and consumers are rejected.')
param entraTenantId string = 'f7812296-5bce-41dc-8102-b1b270e7c4c7'

@description('Server API identifier URI. v2 access tokens must use this audience.')
param entraAudience string = 'api://presidio-redaction-mcp'

@description('Pre-registered Claude client application id.')
param claudeClientId string

@description('Pre-registered Open WebUI client application id.')
param openWebUiClientId string

@description('Pre-registered Grok Bot application id. NonPhi.Caller only.')
param grokClientId string

@description('Digest-pinned proxy image. A floating tag is not accepted.')
param containerImage string

@description('Digest-pinned custom analyzer image built from deploy/presidio/Dockerfile. Not the MCR analyzer.')
param analyzerImage string

@description('Digest-pinned anonymizer image. The analyzer image is not this one.')
param anonymizerImage string

var containerImageDigest = last(split(containerImage, '@sha256:'))
var analyzerImageDigest = last(split(analyzerImage, '@sha256:'))
var anonymizerImageDigest = last(split(anonymizerImage, '@sha256:'))

assert containerImageDigestPinned = indexOf(containerImage, '@sha256:') > 0 && length(containerImageDigest) == 64
assert analyzerImageDigestPinned = indexOf(analyzerImage, '@sha256:') > 0 && length(analyzerImageDigest) == 64
assert anonymizerImageDigestPinned = indexOf(anonymizerImage, '@sha256:') > 0 && length(anonymizerImageDigest) == 64

@description('Container Apps infrastructure subnet. Must be /21 or larger and dedicated.')
param infraSubnetPrefix string = '10.40.0.0/21'

@description('API Management Premium internal subnet. Outside the infrastructure /21.')
param apimSubnetPrefix string = '10.40.8.0/27'

@description('Private endpoint subnet.')
param privateEndpointSubnetPrefix string = '10.40.9.0/24'

var namePrefix = 'prm'
var vnetPrefix = '10.40.0.0/16'
var secretsUserRole = '4633458b-17de-408a-b874-0445c86b69e6'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: '${namePrefix}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-vnet-in'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-all-inbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'allow-entra-jwks'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureActiveDirectory'
          destinationPortRange: '443'
        }
      }
      {
        name: 'allow-monitor'
        properties: {
          priority: 110
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureMonitor'
          destinationPortRange: '443'
        }
      }
      {
        name: 'allow-vnet-out'
        properties: {
          priority: 120
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-all-outbound'
        properties: {
          priority: 4000
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: '${namePrefix}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetPrefix
      ]
    }
    subnets: [
      {
        name: 'cae'
        properties: {
          addressPrefix: infraSubnetPrefix
          networkSecurityGroup: {
            id: nsg.id
          }
          delegations: [
            {
              name: 'cae-delegation'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'apim'
        properties: {
          addressPrefix: apimSubnetPrefix
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
      {
        name: 'private-endpoints'
        properties: {
          addressPrefix: privateEndpointSubnetPrefix
          privateEndpointNetworkPolicies: 'Disabled'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-logs'
  location: location
  properties: {
    retentionInDays: 90
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${namePrefix}kv${uniqueString(resourceGroup().id)}'
  location: location
  properties: {
    tenantId: entraTenantId
    sku: {
      family: 'A'
      name: 'premium'
    }
    enableRbacAuthorization: true
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'None'
    }
  }
}

resource kvDns 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
}

resource kvDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: kvDns
  name: '${namePrefix}-kv-dns'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

resource kvEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${namePrefix}-kv-pe'
  location: location
  properties: {
    subnet: {
      id: '${vnet.id}/subnets/private-endpoints'
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
          privateDnsZoneId: kvDns.id
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
      infrastructureSubnetId: '${vnet.id}/subnets/cae'
    }
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: law.properties.customerId
        sharedKey: law.listKeys().primarySharedKey
      }
    }
    zoneRedundant: false
  }
}

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${namePrefix}-app'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: false
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
      }
    }
    template: {
      containers: [
        {
          name: 'proxy'
          image: containerImage
          resources: {
            cpu: json('1.0')
            memory: '2Gi'
          }
          env: [
            {
              name: 'PRM_ENV'
              value: 'production'
            }
            {
              name: 'PRM_AZURE_INTERNAL'
              value: '1'
            }
            {
              name: 'PRM_AUTH_MODE'
              value: 'entra'
            }
            {
              name: 'PRM_ANALYZER_URL'
              value: 'http://127.0.0.1:3000/analyze'
            }
            {
              name: 'PRM_ANONYMIZER_URL'
              value: 'http://127.0.0.1:3001/anonymize'
            }
            {
              name: 'PRM_ENTRA_TENANT_ID'
              value: entraTenantId
            }
            {
              name: 'PRM_ENTRA_AUDIENCE'
              value: entraAudience
            }
            {
              name: 'PRM_ENTRA_CLIENT_CLAUDE'
              value: claudeClientId
            }
            {
              name: 'PRM_ENTRA_CLIENT_OPEN_WEBUI'
              value: openWebUiClientId
            }
            {
              name: 'PRM_ENTRA_CLIENT_GROK'
              value: grokClientId
            }
          ]
        }
        {
          name: 'analyzer'
          image: analyzerImage
          resources: {
            cpu: json('2.0')
            memory: '4Gi'
          }
          env: [
            {
              name: 'PRESIDIO_BIND'
              value: '127.0.0.1'
            }
            {
              name: 'PRESIDIO_PORT'
              value: '3000'
            }
            {
              name: 'PRESIDIO_SCORE_THRESHOLD'
              value: '0.4'
            }
            {
              name: 'PRESIDIO_RECOGNIZERS'
              value: '/app/recognizers.yaml'
            }
          ]
        }
        {
          name: 'anonymizer'
          image: anonymizerImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            {
              name: 'PORT'
              value: '3001'
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 2
      }
    }
  }
}

resource kvRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, app.id, secretsUserRole)
  scope: kv
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', secretsUserRole)
    principalId: app.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource apim 'Microsoft.ApiManagement/service@2023-05-01-preview' = {
  name: '${namePrefix}-apim'
  location: location
  sku: {
    name: 'Premium'
    capacity: 1
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publisherEmail: 'prm-operators@example.com'
    publisherName: 'presidio-redaction-mcp'
    virtualNetworkType: 'Internal'
    virtualNetworkConfiguration: {
      subnetResourceId: '${vnet.id}/subnets/apim'
    }
    publicNetworkAccess: 'Disabled'
  }
}

resource apimNamedTenant 'Microsoft.ApiManagement/service/namedValues@2023-05-01-preview' = {
  parent: apim
  name: 'entra-tenant-id'
  properties: {
    displayName: 'entra-tenant-id'
    value: entraTenantId
    secret: false
  }
}

resource apimNamedAudience 'Microsoft.ApiManagement/service/namedValues@2023-05-01-preview' = {
  parent: apim
  name: 'entra-audience'
  properties: {
    displayName: 'entra-audience'
    value: entraAudience
    secret: false
  }
}

resource apimNamedClaude 'Microsoft.ApiManagement/service/namedValues@2023-05-01-preview' = {
  parent: apim
  name: 'claude-client-id'
  properties: {
    displayName: 'claude-client-id'
    value: claudeClientId
    secret: false
  }
}

resource apimNamedWebui 'Microsoft.ApiManagement/service/namedValues@2023-05-01-preview' = {
  parent: apim
  name: 'open-webui-client-id'
  properties: {
    displayName: 'open-webui-client-id'
    value: openWebUiClientId
    secret: false
  }
}

resource apimNamedGrok 'Microsoft.ApiManagement/service/namedValues@2023-05-01-preview' = {
  parent: apim
  name: 'grok-client-id'
  properties: {
    displayName: 'grok-client-id'
    value: grokClientId
    secret: false
  }
}

resource apimApi 'Microsoft.ApiManagement/service/apis@2023-05-01-preview' = {
  parent: apim
  name: 'presidio-redaction-mcp'
  properties: {
    displayName: 'presidio-redaction-mcp'
    path: 'mcp'
    protocols: [
      'https'
    ]
    serviceUrl: 'https://${app.properties.configuration.ingress.fqdn}'
    subscriptionRequired: false
  }
}

resource apimPolicy 'Microsoft.ApiManagement/service/apis/policies@2023-05-01-preview' = {
  parent: apimApi
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: loadTextContent('apim-policy.xml')
  }
  dependsOn: [
    apimNamedTenant
    apimNamedAudience
    apimNamedClaude
    apimNamedWebui
    apimNamedGrok
  ]
}

output containerAppName string = app.name
output keyVaultName string = kv.name
output privateIngress bool = !app.properties.configuration.ingress.external
