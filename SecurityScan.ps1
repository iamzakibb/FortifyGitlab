# Step 1: Define variables
$fortifySscUrl = ""
$accessToken = ""
$applicationName = ""
$projectName = ""
$riskLevel = ""
$riskTolerance =""
$categorizationName = ""
$buildArtifactRepoName = ""
$applicationId = ""

# Step 2: Retrieve Application ID from Fortify SSC
function GetApplicationId {
    param (
        [string] $accessToken,
        [string] $fortifySscUrl,
        [string] $applicationName
    )

    $applicationsEndpoint = "$fortifySscUrl/api/v1/projectVersions?start=0&limit=200&fulltextsearch=false&includeInactive=false&myAssignedIssues-false&onlyIfHasIssues-false"

    try {
        $headers = @{
            "Authorization" = "FortifyToken $accessToken"
            "Accept"        = "application/json"
        }
        # Send request to retrieve applications
        $response = Invoke-RestMethod -Uri $applicationsEndpoint -Headers $headers -Method Get
        
        # Check if the request was successful
        if ($response) {
            $applicationsData = $response.data
            
            # Debugging: Output the response data
            Write-Host "Response Data:"
            $applicationsData | Format-Table
            
           
            $LatestApplication = $applicationsData |  Where-Object { $_.project.name -like "*$applicationName*" -or $_.project -like "*$applicationName*" } | Sort-Object -Property Id -Descending | Select-Object -First 1
    
    
            # Print the name of the latest version of the specified application
            if ($LatestApplication) {
                Write-Host "Application id, version and project name: $($LatestApplication.id) $($LatestApplication.name) $($LatestApplication.project.name)"
            }
            else {
                Write-Host "No application found with name '$applicationName'."
            }
        }
        else {
            Write-Host "Failed to retrieve applications. Status code: $($response.StatusCode)"
            Write-Host $response
        }
    }
    catch {
        Write-Host "An error occurred: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $errorResponse = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
    
            $responseBody = $reader.ReadToEnd()
            Write-Host "Response Body: $responseBody"
            Write-Host "Response Headers:"
            $_.Exception.Response.Headers | ForEach-Object {
                Write-Host "$($_.Key): $($_.Value)"
            }
        }
    }
}

# Step 3: Retrieve Latest Scan Result for the Application 
function GetLatestScanResult {
    param (
        [string] $version,
        [string] $applicationId,
        [string] $accessToken,
        [string] $fortifySscUrl
    )

    try {
        $latestScanResultEndpoint = "$fortifySscUrl/api/v1/projectVersions/$applicationId/issues"
        $headers = @{
            "Authorization" = "FortifyToken $accessToken"
            "Accept"        = "application/json"
        }

        $response = Invoke-RestMethod -Uri $latestScanResultEndpoint -Method Get -Headers $headers

        if ($response) {
            $latestScanResult = $response.data
            return $latestScanResult
        }
        else {
            Write-Host "Failed to retrieve latest scan result for this application."
            return $null
        }
    }
    catch {
        Write-Host "An error occurred: $($_.Exception.Message)"
        return $null
    }
}

# Step 4: Compare Latest Scan Result with System Categorization 
function ComparewithSystemCategorization {
    param (
        [object] $latestScanResult,
        [object] $systemCategorization
    )

    $highRisk = $false

    foreach ($item in $latestScanResult) {
        $severity = GetSeverityValue($item.friority)
        $issueName = $item.issueName
        if ($systemCategorization.RiskTolerance -lt $severity) {
            $highRisk = $true
        }
       Write-Host "Latest Scan Result Issue Name: $issueName  ->  Severity: $severity"
    }

    return $highRisk
}

function GetSeverityValue {
    param (
        [string] $severity
    )

    $severityValue = switch ($severity) {
        "Low" { 1 }
        "Medium" { 2 }
        "High" { 3 }
        "Critical" { 4 }
        Default { 0 }
    }
    return $severityValue
}

# Step 5 
$NewApplicationId = GetApplicationId -fortifySscUrl $fortifySscUrl -applicationName $applicationName -accessToken $accessToken 
$applicationVersion = $NewApplicationId.projects.versions | Sort-Object -Property id | Select-Object -Last 1
if ($NewApplicationId) {
    $latestScanResult = GetLatestScanResult -applicationId $NewApplicationId.id -version $applicationVersion.id -fortifySscUrl $fortifySscUrl -accessToken $accessToken

    $systemCategorization = [PSCustomObject]@{
        ProjectName       = $projectName
        RiskLevel         = $riskLevel
        RiskTolerance     = $riskTolerance
        Categorization    = $categorizationName
        BuildArtifactRepo = $buildArtifactRepoName
    }
}

$severity = ComparewithSystemCategorization -latestScanResult $latestScanResult -systemCategorization $systemCategorization

if ($severity) {
    throw "Severity Level greater than Risk Tolerance Level"
}
else {
    Write-Host "Severity level is okay."
}
