$global:exportArray = New-Object System.Collections.ArrayList

function SQL4_1_1 {
    try {
        $effectedResources = @()
        $SQLServerList = Get-AzSqlServer
        foreach ($name in $SQLServerList) {
            $SQLServerAuditingSettings = Get-AzSqlServerAudit -ResourceGroupName $name.ResourceGroupName -ServerName $name.Servername
            if ($SQLServerAuditingSettings.BlobStorageTargetState -ne "enabled" -and $SQLServerAuditingSettings.EventHubTargetState -ne "enabled" -and $SQLServerList.LogAnalyticsTargetState -ne "enabled") {
                $effectedResources += $SQLServerAuditingSettings.ServerName
            }
        }
        $desc = "Enable auditing on SQL Servers."
        $rem = "Ensure that 'Auditing' is set to 'On'"
        AddToExportArray -type "SQLServerAuditingSettings" -cisid "4.1.1" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL4_1_2 {
    try {
        $effectedResources = @()
        $SQLServerList = Get-AzSqlServer
        foreach ($name in $SQLServerList) {
            $SQLServerFirewallRules = Get-AzSqlServerFirewallRule -ResourceGroupName $name.ResourceGroupName -ServerName $name.Servername
            if ($SQLServerFirewallRules.StartIpAddress -eq "0.0.0.0/0" -or $SQLServerFirewallRules.FirewallRuleName -eq "AllowAllWindowsAzureIps") {
                $effectedResources += $SQLServerFirewallRules.ServerName
            }
        }
        $desc = "Ensure that no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)."
        $rem = "Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)"
        AddToExportArray -type "SQLServerFirewallRules" -cisid "4.1.2" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL4_1_3 {
    try {
        $effectedResources = @()
        $SQLServerList = Get-AzSqlServer
        foreach ($name in $SQLServerList) {
            $SQLTDEProtector = Get-AzSqlServerTransparentDataEncryptionProtector -ResourceGroupName $name.ResourceGroupName -ServerName $name.Servername
            if ($SQLTDEProtector.Type -ne 'AzureKeyVault' -and $null -eq $SQLTDEProtector.KeyId) {
                $effectedResources += $SQLTDEProtector.ServerName
            }
        }
        $desc = "Transparent Data Encryption (TDE) with Customer-managed key support provides increased transparency and control over the TDE Protector, increased security with an HSM-backed external service, and promotion of separation of duties."
        $rem = "Ensure SQL server's Transparent Data Encryption (TDE) protector is encrypted with Customer-managed key"
        AddToExportArray -type "SQLTDEProtector" -cisid "4.1.3" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL4_1_4 {
    try {
        $effectedResources = @()
        $SQLServerList = Get-AzSqlServer
        foreach ($name in $SQLServerList) {
            $SQLServer_AD_Admin_info = Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $name.ResourceGroupName -ServerName $name.Servername
            if ($null -eq $SQLServer_AD_Admin_info.DisplayName) {
                $effectedResources += $name.ServerName
            }
        }
        $desc = "Use Azure Active Directory Authentication for authentication with SQL Database to manage credentials in a single place."
        $rem = "Ensure that Azure Active Directory Admin is Configured for SQL Servers"
        AddToExportArray -type "SQLServer_AD_Admin_info" -cisid "4.1.4" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL4_1_5 {
    try {
        $effectedResources = @()
        $SQLServerList = Get-AzSqlServer
        foreach ($name in $SQLServerList) {
            $SQLServerDatabasesList = Get-AzSqlDatabase -ServerName $name.Servername -ResourceGroupName $name.ResourceGroupName
            foreach ($name in $SQLServerDatabasesList) {
                $SQLServerTDEstate = Get-AzSqlDatabaseTransparentDataEncryption  -ServerName $name.Servername -ResourceGroupName $name.ResourceGroupName -DatabaseName $name.DatabaseName
                if ($SQLServerTDEstate.DatabaseName -ne 'master' -and $SQLServerTDEstate.State -ne 'Enabled') {
                    $effectedResources += $SQLServerTDEstate.DatabaseName
                }
            }
        }
        $desc = "Enable Transparent Data Encryption on every SQL server."
        $rem = "Ensure that 'Data encryption' is set to 'On' on a SQL Database"
        AddToExportArray -type "SQLServerTDEstate" -cisid "4.1.5" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL4_1_6 {
    try {
        $effectedResources = @()
        $SQLServerList = Get-AzSqlServer
        foreach ($name in $SQLServerList) {
            $SQLServerAuditingSettings = Get-AzSqlServerAudit -ResourceGroupName $name.ResourceGroupName -ServerName $name.Servername
            if ($SQLServerAuditingSettings.LogAnalyticsTargetState -eq 'Enabled') {
                $SQLServerWorkspaceInfo = Get-AzOperationalInsightsWorkspace | Where-Object { $_.ResourceId -eq 'SQL Server WorkSpaceResourceId' }
                if ($SQLServerWorkspaceInfo.RetentionInDays -lt 90) {
                    $effectedResources += $SQLServerWorkspaceInfo.ServerName
                }
            }
            else {
                if ($SQLServerAuditingSettings.RetentionInDays -lt 90) {
                    $effectedResources += $SQLServerAuditingSettings.ServerName
                }
            }
        }
        $desc = "SQL Server Audit Retention should be configured to be greater than 90 days."
        $rem = "Ensure that 'Auditing' Retention is 'greater than 90 days'"
        AddToExportArray -type "SQLServerWorkspaceInfo" -cisid "4.1.6" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL4_2_1 {
    try {
        $effectedResources = @()
        $SQLServerList = Get-AzSqlServer
        foreach ($name in $SQLServerList) {
            $SQLServerThreatProtectionSettings = Get-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $name.ResourceGroupName -ServerName $name.Servername
            foreach ($name in $SQLServerThreatProtectionSettings) {
                if ($SQLServerThreatProtectionSettings.ThreatDetectionState -ne "enabled") {
                    $effectedResources += $SQLServerThreatProtectionSettings.ServerName
                }
            }
        }
        $desc = "Enable 'Microsoft Defender for SQL' on critical SQL Servers."
        $rem = "Ensure that Microsoft Defender for SQL is set to 'On' for critical SQL Servers"
        AddToExportArray -type "SQLServerThreatProtectionSettings" -cisid "4.2.1" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL4_2_2 {
    try {
        $effectedResources = @()
        $SQLServerList = Get-AzSqlServer
        foreach ($name in $SQLServerList) {
            $SQLServerVulnerabilityAssessmentSettings = Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName $name.ResourceGroupName -ServerName $name.Servername
            if ($null -eq $SQLServerVulnerabilityAssessmentSettings.StorageAccountName) {
                $effectedResources += $SQLServerVulnerabilityAssessmentSettings.ServerName
            }
        }
        $desc = "Enable Vulnerability Assessment (VA) service scans for critical SQL servers and corresponding SQL databases."
        $rem = "Ensure that Vulnerability Assessment (VA) is enabled on a SQL server by setting a Storage Account"
        AddToExportArray -type "SQLServerVulnerabilityAssessmentSettings" -cisid "4.2.2" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}


function SQL4_2_3 {
    try {
        $effectedResources = @()
        $SQLServerList = Get-AzSqlServer
        foreach ($name in $SQLServerList) {
            $SQLServerVulnerabilityAssessmentSettings = Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName $name.ResourceGroupName -ServerName $name.Servername
            if ($SQLServerVulnerabilityAssessmentSettings.RecurringScansInterval -eq 'None') {
                $effectedResources += $SQLServerVulnerabilityAssessmentSettings.ServerName
            }
        }
        $desc = "Enable Vulnerability Assessment (VA) Periodic recurring scans for critical SQL servers and corresponding SQL databases."
        $rem = "Ensure that Vulnerability Assessment (VA) setting 'Periodic recurring scans' is set to 'on' for each SQL server"
        AddToExportArray -type "SQLServerVulnerabilityAssessmentSettings" -cisid "4.2.3" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL4_2_4 {
    try {
        $effectedResources = @()
        $SQLServerList = Get-AzSqlServer
        foreach ($name in $SQLServerList) {
            $SQLServerVulnerabilityAssessmentSettings = Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName $name.ResourceGroupName -ServerName $name.Servername
            if ($null -eq $SQLServerVulnerabilityAssessmentSettings.NotificationEmail) {
                $effectedResources += $SQLServerVulnerabilityAssessmentSettings.ServerName
            }
        }
        $desc = "Configure 'Send scan reports to' with email ids of concerned data owners/stakeholders for a critical SQL servers."
        $rem = "Ensure that Vulnerability Assessment (VA) setting 'Send scan reports to' is configured for a SQL server"
        AddToExportArray -type "SQLServerVulnerabilityAssessmentSettings" -cisid "4.2.4" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL4_2_5 {
    try {
        $effectedResources = @()
        $SQLServerList = Get-AzSqlServer
        foreach ($name in $SQLServerList) {
            $SQLServerVulnerabilityAssessmentSettings = Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName $name.ResourceGroupName -ServerName $name.Servername
            if ($SQLServerVulnerabilityAssessmentSettings.EmailAdmins -ne 'true') {
                $effectedResources += $SQLServerVulnerabilityAssessmentSettings.ServerName
            }
        }
        $desc = "Enable Vulnerability Assessment (VA) setting 'Also send email notifications to admins and subscription owners'."
        $rem = "Ensure that Vulnerability Assessment (VA) setting 'Also send email notifications to admins and subscription owners' is set for each SQL Server"
        AddToExportArray -type "SQLServerVulnerabilityAssessmentSettings" -cisid "4.2.5" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL_4_3_1 {
    try {
        $effectedResources = @()
        $PostGreSQLServerInfo = Get-AzPostgreSqlServer
        foreach ($name in $PostGreSQLServerInfo) {
            if ($name.SslEnforcement -ne 'Enabled') {
                $effectedResources += $name.Name
            }
        }
        $desc = "Enable SSL connection on PostgreSQL Servers."
        $rem = "Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server"
        AddToExportArray -type "PostGreSQLServerInfo" -cisid "4.3.1" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL_4_3_2 {
    try {
        $effectedResources = @()
        $RG = Get-AzResourceGroup
        foreach ($names in $RG) {
            $PostgreSQLServerInfo = Get-AzPostgreSqlServer -ResourceGroupName $names.ResourceGroupName
            foreach ($name in $PostgreSQLServerInfo) {
                $PostgreSQLConfigurationInfo = Get-AzPostgreSqlConfiguration -Name log_checkpoints -ServerName $name.Name -ResourceGroupName $names.ResourceGroupName
                if ($PostgreSQLConfigurationInfo.Value -ne 'on' ) {
                    $effectedResources += $name.Name
                }
            }
        }
        $desc = "Enable log_checkpoints on PostgreSQL Servers."
        $rem = "Ensure Server Parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server"
        AddToExportArray -type "PostgreSQLConfigurationInfo" -cisid "4.3.2" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL_4_3_3 {
    try {
        $effectedResources = @()
        $RG = Get-AzResourceGroup
        foreach ($names in $RG) {
            $PostgreSQLServerInfo = Get-AzPostgreSqlServer -ResourceGroupName $names.ResourceGroupName
            foreach ($name in $PostgreSQLServerInfo) {
                $PostgreSQLConfigurationInfo = Get-AzPostgreSqlConfiguration -Name log_connections -ServerName $name.Name -ResourceGroupName $names.ResourceGroupName
                if ($PostgreSQLConfigurationInfo.Value -ne 'on' ) {
                    $effectedResources += $name.Name
                }
            }
        }
        $desc = "Enable log_connections on PostgreSQL Servers."
        $rem = "Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server"
        AddToExportArray -type "PostgreSQLConfigurationInfo" -cisid "4.3.3" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL_4_3_4 {
    try {
        $effectedResources = @()
        $RG = Get-AzResourceGroup
        foreach ($names in $RG) {
            $PostgreSQLServerInfo = Get-AzPostgreSqlServer -ResourceGroupName $names.ResourceGroupName
            foreach ($name in $PostgreSQLServerInfo) {
                $PostgreSQLConfigurationInfo = Get-AzPostgreSqlConfiguration -Name log_disconnections -ServerName $name.Name -ResourceGroupName $names.ResourceGroupName
                if ($PostgreSQLConfigurationInfo.Value -ne 'on' ) {
                    $effectedResources += $name.Name
                }
            }
        }
        $desc = "Enable log_disconnections on PostgreSQL Servers."
        $rem = "Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server"
        AddToExportArray -type "PostgreSQLConfigurationInfo" -cisid "4.3.4" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL_4_3_5 {
    try {
        $effectedResources = @()
        $RG = Get-AzResourceGroup
        foreach ($names in $RG) {
            $PostgreSQLServerInfo = Get-AzPostgreSqlServer -ResourceGroupName $names.ResourceGroupName
            foreach ($name in $PostgreSQLServerInfo) {
                $PostgreSQLConfigurationInfo = Get-AzPostgreSqlConfiguration -Name connection_throttling -ServerName $name.Name -ResourceGroupName $names.ResourceGroupName
                if ($PostgreSQLConfigurationInfo.Value -ne 'on' ) {
                    $effectedResources += $name.Name
                }
            }
        }
        $desc = "Enable connection_throttling on PostgreSQL Servers."
        $rem = "Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server"
        AddToExportArray -type "PostgreSQLConfigurationInfo" -cisid "4.3.5" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL_4_3_6 {
    try {
        $effectedResources = @()
        $RG = Get-AzResourceGroup
        foreach ($names in $RG) {
            $PostgreSQLServerInfo = Get-AzPostgreSqlServer -ResourceGroupName $names.ResourceGroupName
            foreach ($name in $PostgreSQLServerInfo) {
                $PostgreSQLConfigurationInfo = Get-AzPostgreSqlConfiguration -Name log_retention_days -ServerName $name.Name -ResourceGroupName $names.ResourceGroupName
                if ($PostgreSQLConfigurationInfo.Value -le 3 ) {
                    $effectedResources += $name.Name
                }
            }
        }
        $desc = "Enable log_retention_days on PostgreSQL Servers."
        $rem = "Ensure Server Parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server"
        AddToExportArray -type "PostgreSQLConfigurationInfo" -cisid "4.3.6" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL_4_3_8 {
    try {
        $effectedResources = @()
        $PostgreSQLServerInfo = Get-AzPostgreSqlServer
        foreach ($name in $PostgreSQLServerInfo) {
            if ($name.InfrastructureEncryption -ne 'Enabled') {
                $effectedResources += $name.Name
            }
        }
        $desc = "Enable encryption at rest for PostgreSQL Databases."
        $rem = "Ensure 'Infrastructure double encryption' for PostgreSQL Database Server is 'Enabled'"
        AddToExportArray -type "PostgreSQLServerInfo" -cisid "4.3.8" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL_4_4_1 {
    try {
        $effectedResources = @()
        $MySQLServerInformation = Get-AzMySqlServer
        foreach ($name in $MySQLServerInformation) {
            if ($name.SslEnforcement -ne 'Enabled') {
                $effectedResources += $name.Name
            }
        }
        $desc = "Enable SSL connection on MYSQL Servers."
        $rem = "Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server"
        AddToExportArray -type "MySQLServerInformation" -cisid "4.4.1" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
    }
    catch {
        Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
        Write-Host $_
    }
}

function SQL_4_4_2 {
    try {
        $effectedResources = @()
        $RG = Get-AzResourceGroup
        foreach ($names in $RG) {
            $MySQLflexibleServerInfo = Get-AzMySqlFlexibleServer -ResourceGroupName $names.ResourceGroupName
            foreach ($name in $MySQLflexibleServerInfo) {
                $SQLConfig = Get-AzMySqlFlexibleServerConfiguration -Name tls_version -ServerName $name.Name -ResourceGroupName $names.ResourceGroupName
                if ($SQLConfig.Value -ne 'TLSV1.2' ) {
                    $effectedResources += $name.Name
                }
            }
        }
        $desc = "Ensure TLS version on MySQL flexible servers is set to the default value."
        $rem = "Ensure 'TLS Version' is set to 'TLSV1.2' for MySQL flexible Database Server"
        AddToExportArray -type "MySQLflexibleServerInfo" -cisid "4.4.2" -description $desc -subSeverity "Medium" -status (StatusCheck -inputArray $effectedResources) -remidiation $rem -effectedResource $effectedResources
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


try {

    #SQLServerAuditingSettings
    SQL4_1_1 > $null

    #SQLServerFirewallRules
    SQL4_1_2 > $null

    #SQLTDEProtector
    SQL4_1_3 > $null

    #SQLServer_AD_Admin_info
    SQL4_1_4 > $null

    #SQLServerTDEstate
    SQL4_1_5 > $null

    #SQLServerWorkspaceInfo
    SQL4_1_6 > $null

    #SQLServerThreatProtectionSettings
    SQL4_2_1 > $null

    #SQLServerVulnerabilityAssessmentSettings
    SQL4_2_2 > $null
    SQL4_2_3 > $null
    SQL4_2_4 > $null
    SQL4_2_5 > $null

    #PostgreSQLConfigurationInfo
    SQL_4_3_1 > $null

    #PostgreSQLConfigurationInfo
    SQL_4_3_2 > $null
    SQL_4_3_3 > $null
    SQL_4_3_4 > $null
    SQL_4_3_5 > $null
    SQL_4_3_6 > $null


    #PostgreSQLServerInfo
    SQL_4_3_8 > $null

    #MySQLServerInformation
    SQL_4_4_1 > $null

    #MySQLflexibleServerInfo
    SQL_4_4_2 > $null

    $global:exportArray
}
catch {
    Write-Host (Get-Date -UFormat '%y_%m_%d') '- The following error occured: '
    Write-Host $_
}