$global:exportArray = New-Object System.Collections.ArrayList


function SQL_4_3_8 {
    try {
        $effectedResources = @()
        $SQLServerList = Get-AzPostgreSqlServer
        foreach ($name in $SQLServerList) {
            if($name) {
                $effectedResources += $name.Name
            }
        }
        $desc = "Enable Vulnerability Assessment (VA) setting 'Also send email notifications to admins and subscription owners'."
        $rem = "Ensure that Vulnerability Assessment (VA) setting 'Also send email notifications to admins and subscription owners' is set for each SQL Server"
        AddToExportArray -type "SQLServerVulnerabilityAssessmentSettings" -cisid "4.3.8" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}


function StatusCheck {
    param (
        $inputArray    
    )
    try {
        if ($inputArray.count -eq 0) { return 'Pass' } else { return 'Failed' }
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}



function AddToExportArray {
    param (
        $type,
        $cisid,
        $description,
        $subSeverity,
        $status,
        $remidiation,
        $effectedResource
    )
    $global:exportArray.Add([PSCustomObject]@{
            "Type"              = $type
            "CISID"             = $cisid
            "Description"       = $description
            "SubSeverity"       = $subSeverity
            "Status"            = $status
            "remidiation"       = $remidiation
            "effectedResources" = $effectedResources
        })
}


########### Main ###########

try {
    
    SQL_4_3_8 > $null

    $global:exportArray
}
catch {
    Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
    Write-Host $_
}