$statusSuccess="Success"
$statusFailed="Failed"
$statusInProgress="InProgress"

# Retry won't be done if retry count reaches the following threshold
$consectiveFailureThreshold=3

# Read TS environment variables from environment.txt
$envProperties = Get-Content -Path "./environment.txt" | Where-Object { $_ -notlike '#*' }
foreach ($envProperty in $envProperties) {
    if ($envProperty.StartsWith("SERVERURL=")) {
        $regexServerFqdn = [regex]'SERVERURL=(.*)'
        $serverfqdn = $regexServerFqdn.Match($envProperty).Groups[1].Value
    } elseif ($envProperty.StartsWith("SITEURL=")) {
        $regexSiteUrl = [regex]'SITEURL=(.*)'
        $siteurl = $regexSiteUrl.Match($envProperty).Groups[1].Value
    } elseif ($envProperty.StartsWith("APIVERSION=")) {
        $regexApiVersion = [regex]'APIVERSION=(.*)'
        $apiversion = $regexApiVersion.Match($envProperty).Groups[1].Value
    } elseif ($envProperty.StartsWith("USERNAME=")) {
        $regexTsUsername = [regex]'USERNAME=(.*)'
        $tsusername = $regexTsUsername.Match($envProperty).Groups[1].Value
    }
}

# Allow to connect over TLS1.1 and TLS1.2
[Net.ServicePointManager]::SecurityProtocol = @([Net.SecurityProtocolType]::Ssl3,[Net.SecurityProtocolType]::Tls,[Net.SecurityProtocolType]::Tls11,[Net.SecurityProtocolType]::Tls12)

# Before start to processing, delete old log files 
$files = Get-ChildItem -Recurse -File -Include *.log | Where-Object { $_.Name -match '^\d{4}-\d{2}-\d{2}' }

foreach ($file in $files) {
    $dateString = [regex]::Match($file.Name, "\d{4}-\d{2}-\d{2}").Value
    $fileDate = [DateTime]::ParseExact($dateString, "yyyy-MM-dd", $null)
    $daysDifference = (Get-Date).Date.Subtract($fileDate.Date).Days

    if ($daysDifference -ge 3) {
        Remove-Item -Path $file.FullName -Force
    }
}

# create log file as <yyyy-mm-dd>.log
$currentDate = Get-Date -Format 'yyyy-MM-dd'
$currentLogfile = "$currentDate.log"
if (-not (Test-Path $currentLogfile)) {
    New-Item -ItemType File -Path $currentLogfile > $null
}
$currentDateTimeString = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"$currentDateTimeString start running the script" | Out-File -FilePath $currentLogfile -Append


# Step1: Signing in to Tableau Server
$patFile = "pat.txt"
$passwordFile = "password.txt"
$requestBody = ""

if (Test-Path $patFile) {
    # read pat name and value from pat.txt
    $patProperties = Get-Content -Path $patFile | Where-Object { $_ -notlike '#*' }
    foreach ($patProperty in $patProperties) {
        if ($patProperty.StartsWith("patName=")) {
            $regexPatName = [regex]'patName=(.*)'
            $patName = $regexPatName.Match($patProperty).Groups[1].Value
        } elseif ($patProperty.StartsWith("patSecret=")) {
            $regexPatSecret = [regex]'patSecret=(.*)'
            $patSecret = $regexPatSecret.Match($patProperty).Groups[1].Value
        }
    }
    $requestBody = "<tsRequest><credentials personalAccessTokenName=`""+$patName+"`" personalAccessTokenSecret=`""+$patSecret+"`" ><site contentUrl=`""+$siteurl+"`" /></credentials></tsRequest>"
} elseif (Test-Path $passwordFile) {
    # read user password from password.txt
    $password = Get-Content -Path $passwordFile -Raw
    $requestBody = "<tsRequest><credentials name=`""+$tsusername+"`" password=`""+$password+"`" ><site contentUrl=`""+$siteurl+"`" /></credentials></tsRequest>"
} else {
    "$currentDateTimeString neither $patFile nor $passwordFile exist. End processing." | Out-File -FilePath $currentLogfile -Append
    exit 1
}

# build a request url and body for signing-in from local file
$urlSignin = $serverfqdn+"/api/"+$apiversion+"/auth/signin"

# send signin request
$responseSignin = Invoke-WebRequest -Uri $urlSignin -Method POST -Body $requestBody -ContentType 'application/xml'

# check the HTTP status code
if ($responseSignin.StatusCode -ne 200) {
    $currentDateTimeString = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$currentDateTimeString signing-in failed with status code ${responseSignins}.StatusCode" | Out-File -FilePath $currentLogfile -Append
    exit 2
}

# Step2: general preparations for the next request
# extract token and siteid from the response
$tokenRegex = [regex]'<credentials token="(.*?)"'
$token = $tokenRegex.Match($responseSignin.Content).Groups[1].Value

$siteidRegex = [regex]'<site id="(.*?)" '
$siteid = $siteidRegex.Match($responseSignin.Content).Groups[1].Value

# set token in the request header
$headers = @{
    "X-tableau-auth" = $token
}


# Step3: prepare for querying the flow run results in current date
# get flow run results (A) current date (B) increase page size since the customer runs more thatn 100 flows in a daily basis (C) sort asc order by completedAt
$currentDate = Get-Date -Format 'yyyy-MM-dd'
$urlGetflowruns = "$serverfqdn/api/$apiversion/sites/$siteid/flows/runs?filter=startedAt:gte:${currentDate}T00:00:00Z&pageSize=500&sort=completedAt:asc" 

# send get flow runs request
$responseGetflowruns = Invoke-WebRequest -Uri $urlGetflowruns -Headers $headers


# Step4: analyze flow run results
$resulsHashCurrentExecution = @{}
$allResultsByFlow = [System.Collections.Hashtable]::new()
$failedResultsByFlow = [System.Collections.Hashtable]::new()
$latestResultsByFlow = [System.Collections.Hashtable]::new()

# analyze each <flowRuns> result with $status(false).
$responseGetflowruns.Content |
    ForEach-Object {[regex]::Matches($_, '<flowRuns (.*?)/>')} |
        ForEach-Object {

            $failedRunInfo = $_.Groups[1].value
            $regexFlowRunId = [regex]'id="(.*?)"'
            $regexFlowId = [regex]'id=".*" flowId="(.*?)"'
            $regexCompletedAt = [regex]'completedAt="(.*?)Z'
            $regexResultStatus = [regex]'status="(.*?)"'

            $flowRunId = $regexFlowRunId.Match($failedRunInfo).Groups[1].Value
            $flowId = $regexFlowId.Match($failedRunInfo).Groups[1].Value
            $resultStatus = $regexResultStatus.Match($failedRunInfo).Groups[1].Value
            if ($resultStatus -match $statusInProgress) {
                $completedAt = "9999-12-31T23:59:59"
            } else {
                $completedAt = $regexCompletedAt.Match($failedRunInfo).Groups[1].Value
            }

            ## For $allResultsByFlow
            #
            if ( -not ($allResultsByFlow.ContainsKey($flowId)) ) {
                $allResultsByFlow.Add($flowId, [System.Collections.ArrayList]::new()) > $null
            }
            $allResultsByFlow[$flowId].Add($completedAt +"#"+ $resultStatus) > $null

            ## For $failedResultsByFlow
            if ($resultStatus -match $statusFailed) {
                if ( -not ($failedResultsByFlow.ContainsKey($flowId)) ) {
                    $failedResultsByFlow.Add($flowId, [System.Collections.ArrayList]::new())  > $null
                }
                $failedResultsByFlow[$flowId].Add($completedAt +"#"+ $resultStatus)  > $null
            }

            ## For $latestResultsByFlow
            # Newly create hashtable for each flow and add the initial info (status and completedAt)
            if ( -not ($latestResultsByFlow.ContainsKey($flowId)) ) {
                $latestResultsByFlow.Add($flowId, [System.Collections.ArrayList]::new())  > $null
                $latestResultsByFlow[$flowId].Add($resultStatus)  > $null
                $latestResultsByFlow[$flowId].Add($completedAt)  > $null
            } else {
                # Compare current flow's date of completedAt and the date in ArrayList (This is not mandatory since )
                $currentFlowCompletedAt = [DateTime]::ParseExact($completedAt, "yyyy-MM-ddTHH:mm:ss", $null)
                $completedAtInArray =  [DateTime]::ParseExact($latestResultsByFlow[$flowId][1], "yyyy-MM-ddTHH:mm:ss", $null)

                if ($completedAtInArray -le $currentFlowCompletedAt) {
                    $latestResultsByFlow[$flowId][0]=$resultStatus
                    $latestResultsByFlow[$flowId][1]=$completedAt
                }
            }
        }

# Step5: see if the failed flows match whitelist urls

# Read whitelist URLs from whitelist.txt
$whitelistArray = [System.Collections.ArrayList]::new()
$whitelistUrls = Get-Content -Path "./whitelist.txt" | Where-Object { $_ -notlike '#*' }
foreach ($whitelistUrl in $whitelistUrls) {
    if ($whitelistUrl.Contains("/#/site/")) {
        $extractedUrl = [regex]::Match($whitelistUrl, "(/#/site/[^/#]+/flows/[^/#]+)").Groups[1].Value
    } else {
        $extractedUrl = [regex]::Match($whitelistUrl, "(/#/flows/[^/#]+)").Groups[1].Value
    }
    $whitelistArray.Add($extractedUrl)  > $null
}

# get flow (A) flowId (B) web page URL of the flow (C) increase page size since the customer runs more thatn 100 flows in a daily basis
$urlGetflows = "$serverfqdn/api/$apiversion/sites/$siteid/flows?pageSize=500" 

# send get flows request
$responseGetflows = Invoke-WebRequest -Uri $urlGetflows -Headers $headers

# extract url into hashmap (1)flowID (2)url of the flow. (loop for each flow information)
$hashmapFlowUrl = [System.Collections.Hashtable]::new()
$responseGetflows.Content |
    ForEach-Object {[regex]::Matches($_, '<flow (.*?)>')} |
        ForEach-Object {
            $flowInfo = $_.Groups[1].value
            $regexFlowId = [regex]'id="(.*?)"'
            $regexFlowUrl = [regex]'webpageUrl="https?://[^/#]+(.*?)"'

            $flowId = $regexFlowId.Match($flowInfo).Groups[1].Value
            $flowUrl = $regexFlowUrl.Match($flowInfo).Groups[1].Value
            $hashmapFlowUrl.Add($flowId, $flowUrl)  > $null
        }


# Iterate over each value using a foreach loop
foreach ($flowKey in $latestResultsByFlow.Keys ) {

    $consecutiveFailures=$true
    $isInWhitelist=$false

    # latest result shows Failed
    if ($latestResultsByFlow[$flowKey][0] -match $statusFailed) {
        # The flow failed more than $consectiveFailureThreshold times
        if($failedResultsByFlow[$flowKey].Count -ge $consectiveFailureThreshold) {
            # The flow failure is consecutive $consectiveFailureThreshold times
            for ($i = ($allResultsByFlow[$flowKey].Count - 1); $i -gt (($allResultsByFlow[$flowKey].Count - 1) - $consectiveFailureThreshold); $i--) {
                # If flow succeeded within latest $consectiveFailureThreshold times, it should re-run (not consecutive failures)
                if ($allResultsByFlow[$flowKey][$i].Contains($statusSuccess)) {
                    $consecutiveFailures=$false
                    break
                }
            }
        } else {
            $consecutiveFailures=$false
        }
    }
    # iterate over the 1st hash by key and see if the url is icluded in whitelist 
    foreach ($whitelistItem in $whitelistArray ) {
        if($whitelistItem.Contains($hashmapFlowUrl[$flowKey])) {  
            $isInWhitelist = $true
            break
        }
    }
    # if (1) the flow url is in whitelist AND (2) not consecutive failures
    if (($consecutiveFailures -eq $false) -and ($isInWhitelist -eq $true)) {
        # requet URL for running the flow
        $urlRunflow = $serverfqdn+"/api/"+$apiversion+"/sites/"+$siteid+"/flows/"+$flowKey+"/run"
   
        # request body for running the flow
        $requestBodyRunflow = "<tsRequest><flowRunSpec flowId=`"$flowKey`"></flowRunSpec></tsRequest>"

        # send run now flow request
        $responseRunflow = Invoke-WebRequest -Uri $urlRunflow -Headers $headers -Method POST -Body $requestBodyRunflow

        $currentDateTimeString = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$currentDateTimeString run flowId: ${flowKey}, flowURL: " + $hashmapFlowUrl[$flowKey] | Out-File -FilePath $currentLogfile -Append
    }
}
