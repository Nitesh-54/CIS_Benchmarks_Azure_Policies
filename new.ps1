$global:exportArray = New-Object System.Collections.ArrayList

# function SQL_4_4_1 {
#     try {
#         $effectedResources = @()
#         $SQLServerList = Get-AzSqlServer
#         foreach ($name in $SQLServerList) {
#             $SQLServerInformation = Get-AzMySqlServer -ResourceGroupName $name.ResourceGroupName
#             if ($SQLServerInformation.SslEnforcement -eq 'Disabled') {
#                 $effectedResources += $SQLServerInformation.Name
#             }
#         }
#         $desc = "Enable SSL connection on MYSQL Servers."
#         $rem = "Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server"
#         AddToExportArray -type "SQLServerInformation" -cisid "4.4.1" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
#     }
#     catch {
#         Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
#         Write-Host $_
#     }
# }
function SQL_4_4_2 {
    try {
        $effectedResources = @()
            $SQLServerInformation = Get-AzMySqlFlexibleServer
            if ($SQLServerInformation) {
                if ($SQLServerInformation.Version -ne 'TLSV1.2') {
                    $effectedResources += $SQLServerInformation.ServerName
                }
            }
        $desc = "Ensure TLS version on MySQL flexible servers is set to the default value."
        $rem = "Ensure 'TLS Version' is set to 'TLSV1.2' for MySQL flexible Database Server"
        AddToExportArray -type "SQLServerInformation" -cisid "4.4.2" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
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
    
    # SQL_4_4_1
    SQL_4_4_2

    $global:exportArray
}
catch {
    Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
    Write-Host $_
}