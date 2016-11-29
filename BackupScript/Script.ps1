#
# Script.ps1
#
#
# Script.ps1
#

[cmdletbinding()]
PARAM()

Import-Module AifcoManagementTools
function get-config
{
	param(
		[parameter(Mandatory = $true)]
		[string]$path
	)

    [xml]$xmlConfig = Get-Content $path
	if(-not [system.io.file]::Exists($path))
	{
		throw [System.ArgumentException]"No se encontró el archivo de configuración"
	}
    $sourceFolder = $xmlConfig.configuration.source.folder.Trim()
    $destination = $xmlConfig.configuration.destination.Trim()
    $logfile = $xmlConfig.configuration.logfile.Trim()
    $copylogfile = $xmlConfig.Configuration.CopyLogFile.Trim()
    $NetworkUser = $xmlConfig.Configuration.NetworkUser.Trim()
    $NetworkPassword = $xmlConfig.Configuration.NetworkPassword.Trim()
    $IsExternalNetwork = [System.Convert]::ToBoolean($xmlConfig.Configuration.IsExternalNetwork.Trim())

    for($i = 0; $i -lt $sourceFolder.Count; $i++)
    {
        if(-not ($sourceFolder[$i].LastIndexOf("\") -eq ($sourceFolder[$i].Length -1)))
        {
            $sourceFolder[$i] += "\"    
        }
    }

    if(-not($destination.LastIndexOf("\") -eq ($destination.Length -1)) -and $configuration.IsExternalNetwork -eq $false)
    {
        $destination += "\"
    }
	
	$config = New-Object system.object
    $config | Add-Member -MemberType NoteProperty -Name NetworkUser -Value $NetworkUser
    $config | Add-Member -MemberType NoteProperty -Name NetworkPassword -Value $NetworkPassword
    $config | Add-Member -MemberType NoteProperty -Name IsExternalNetwork -Value $IsExternalNetwork
	$config | Add-Member -MemberType NoteProperty -Name SourcePath -Value $sourceFolder
	$config | Add-Member -MemberType NoteProperty -Name DestinationPath -value $destination
	$config | Add-Member -MemberType NoteProperty -Name LogFile -Value $logfile
	$config | Add-Member -MemberType NoteProperty -Name CopyLogFile -Value $copylogfile
	$config.PSObject.TypeNames.Insert(0,"Configuration")
	return $config
}

function Validate-Configuration
{
	param(
		[parameter(Mandatory = $true,Position = 0)]
		$config
	)
	if(-not [System.IO.Directory]::Exists($config.DestinationPath) -and -not $config.IsExternalNetwork)
	{
		throw [System.ArgumentException]("No se encontró el directorio destino: {0}" -f $config.DestinationPath)
	}
	if(-not [System.IO.Directory]::Exists([System.IO.Path]::GetDirectoryName($config.LogFile)) -and -not [string]::IsNullOrWhiteSpace([System.IO.Path]::GetDirectoryName($config.LogFile)))
	{
		throw [System.ArgumentException]("No se encontró el directorio destino para el log: {0}" -f $config.LogFile)
	}
	if(-not [System.IO.Directory]::Exists([System.IO.Path]::GetDirectoryName($config.CopyLogFile)) -and -not [string]::IsNullOrWhiteSpace([System.IO.Path]::GetDirectoryName($config.CopyLogFile)))
	{
		throw [System.ArgumentException]("No se encontró el directorio destino para el log: {0}" -f $config.CopyLogFile)
	}
	foreach($directory in $config.SourcePath)
	{
		if(-not [System.IO.Directory]::Exists($directory))
		{
			throw [System.ArgumentException]("No se encontró el directorio origen: {0}" -f $directory)
		}
	}
	return $true
}



$configurationFile = [System.IO.Path]::Combine($PSScriptRoot, ".\config.xml")
$configuration = get-config $configurationFile
$copyArgs = (("/LOG+:{0}" -f $configuration.CopyLogFile),"/mir","/z","/r:10","/w:5")
Write-Log -Information ("--------------------------{0}---------------------" -f (Get-Date).ToString("dd-MM-yy hh:mm:ss") ) -Path $configuration.LogFile
Write-Verbose ("--------------------------{0}---------------------" -f (Get-Date).ToString("dd-MM-yy hh:mm:ss") )
Write-Log -Information "Iniciando copia de Seguridad..." -Path $configuration.LogFile
Write-Verbose "Iniciando copia de Seguridad..."

try
{
	if(Validate-Configuration $configuration -ErrorAction Stop)
	{	
        if($configuration.IsExternalNetwork)
        {
            [byte[]]$key = @(181, 49, 125, 179, 16, 225, 61, 182, 152, 32, 215, 244, 204, 248, 90, 252, 6, 188, 121, 43, 136, 155, 159, 175, 212, 115, 40, 37, 96, 124, 82, 230)
            $password = $configuration.NetworkPassword | ConvertTo-SecureString -Key $key
            $credentials = New-Object System.Management.Automation.PSCredential $configuration.NetworkUser, $password

            Write-Log -Information ("Opción de red externa detectada... conectando a carpeta remota como: {0}" -f $credentials.GetNetworkCredential().UserName) -Path $configuration.LogFile
            Write-Verbose ("Opción de red externa detectada... conectando a carpeta remota como: {0}" -f $credentials.GetNetworkCredential().UserName)
            
            $useParams = @("use", $configuration.DestinationPath, ("/user:{0}" -f $credentials.GetNetworkCredential().UserName),$credentials.GetNetworkCredential().Password)
            $result = &net $useParams
            Write-Log -Information ("Resultado de la conexion remota: {0}" -f $result) -Path $configuration.LogFile
            Write-Verbose ("Resultado de la conexion remota: {0}" -f $result)
        }

		foreach($folder in $configuration.SourcePath)
		{
			$folderInfo = New-Object System.IO.DirectoryInfo -ArgumentList $folder
			$destinationFolder = [System.IO.Path]::Combine($configuration.DestinationPath, $folderInfo.Name)
			if(-not [System.IO.Directory]::Exists($destinationFolder))
			{
                
                Write-Log -Information ("No se encontró la carpeta {0} en el directorio destino, creando carpeta..." -f $folderInfo.Name) -Path $configuration.LogFile
                Write-Verbose ("No se encontró la carpeta {0} en el directorio destino, creando carpeta..." -f $folderInfo.Name)
				New-Item -ItemType Directory -Path $destinationFolder -ErrorAction Stop| Out-Null                
                Write-Log -Information ("Carpeta Creada Exitosamente...") -Path $configuration.LogFile
                Write-Verbose  ("Carpeta Creada Exitosamente...")
			}
            $before = Get-Date
			Write-Log -Information ("Iniciando copia de seguridad de la carpeta {0} en {1}" -f $folder, $destinationFolder) -Path $configuration.LogFile
            Write-Verbose ("Iniciando copia de seguridad de la carpeta {0} en {1}" -f $folder, $destinationFolder)
			&robocopy.exe $folder $destinationFolder $copyArgs  | Out-Null
			$after = Get-Date
            Write-Log -Information ("Copia completada en: {0} favor de revisar log de copia {1} para información mas detallada" -f $after.Subtract($before).ToString(), $configuration.CopyLogFile) -Path $configuration.LogFile 
            Write-Verbose ("Copia completada en: {0} favor de revisar log de copia {1} para información mas detallada" -f $after.Subtract($before).ToString(), $configuration.CopyLogFile)            
		}
        if($configuration.IsExternalNetwork)
        {
            Write-Log -Information ("Desconectando carpeta remota...") -Path $configuration.LogFile  
            Write-Verbose ("Desconectando carpeta remota...")          
            $useParams = @("use", $configuration.DestinationPath, "/DELETE")
            $result =  &net $useParams 
            Write-Log -Information ("Resultado de la conexion remota: {0}" -f $result) -Path $configuration.LogFile
            Write-Verbose ("Resultado de la conexion remota: {0}" -f $result) 
        }
	}else{
		Write-Log -Error "El archivo de configuración es invalido... abortando copia de seguridad..." -Path $configuration.LogFile
        Write-Error  "El archivo de configuración es invalido... abortando copia de seguridad..."
	}   
	
}
catch
{
	 $_.exception.message |foreach{ Write-Log -Error ("Ocurrió un error: {0}" -f $_) -Path $configuration.LogFile}
     $_.exception.message |foreach{ Write-Verbose ("Ocurrió un error: {0}" -f $_) }
}