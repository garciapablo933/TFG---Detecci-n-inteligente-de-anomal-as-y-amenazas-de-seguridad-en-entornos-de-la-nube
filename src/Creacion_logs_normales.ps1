# ==========================================================
# SCRIPT DE GENERACIÓN DE DATASET SINTÉTICO - LOGS NORMALES
# Versión 3.1 - Período extendido para ~400k registros
# ----------------------------------------------------------
# ESQUEMA MAESTRO (13 columnas — idéntico en ambos scripts):
# CustomTimestamp, UserPrincipalName, Department, Office,
# Country, Operation, Resource, Result, IP_Address,
# NetworkType, Device_ID, Resource_Criticality, UserProfile
# ----------------------------------------------------------
# Objetivo: ~400.000 registros
# Período:  2026-01-01 al 2026-02-11 (42 días)
# Las amenazas están en 2026-01-05 al 2026-01-25 → quedan
# en el centro del período normal, sin solapamiento extraño.
# ==========================================================

# ----------------------------------------------------------
# SECCIÓN 1: CONFIGURACIÓN GLOBAL
# ----------------------------------------------------------

$sedes = @{
    "España"      = @{ UTCOffset = 1;  CorpSubnet = "10.1.1"; VPNSubnet = "172.16.1"; City = "Madrid";      CC = "ES" }
    "Alemania"    = @{ UTCOffset = 1;  CorpSubnet = "10.2.1"; VPNSubnet = "172.16.2"; City = "Berlin";      CC = "DE" }
    "Reino Unido" = @{ UTCOffset = 0;  CorpSubnet = "10.3.1"; VPNSubnet = "172.16.3"; City = "London";      CC = "GB" }
    "Italia"      = @{ UTCOffset = 1;  CorpSubnet = "10.4.1"; VPNSubnet = "172.16.4"; City = "Milan";       CC = "IT" }
    "Polonia"     = @{ UTCOffset = 1;  CorpSubnet = "10.5.1"; VPNSubnet = "172.16.5"; City = "Warsaw";      CC = "PL" }
    "EEUU-Este"   = @{ UTCOffset = -5; CorpSubnet = "10.6.1"; VPNSubnet = "172.16.6"; City = "New York";    CC = "US" }
    "EEUU-Oeste"  = @{ UTCOffset = -8; CorpSubnet = "10.7.1"; VPNSubnet = "172.16.7"; City = "Los Angeles"; CC = "US" }
}

$contenedoresPorDept = @{
    "IT"          = @("/it-sistemas/config/",          "/it-sistemas/scripts/",         "/it-sistemas/backups/")
    "Finance"     = @("/finanzas/facturas/",            "/finanzas/presupuestos/",       "/finanzas/nominas/")
    "HR"          = @("/recursos-humanos/contratos/",   "/recursos-humanos/nominas/",    "/recursos-humanos/expedientes/")
    "Sales"       = @("/shared/plantillas/",            "/shared/informes_publicos/",    "/shared/")
    "Marketing"   = @("/marketing/campanas/",           "/marketing/assets/",            "/marketing/analytics/")
    "Legal"       = @("/finanzas/presupuestos/",        "/shared/plantillas/",           "/shared/")
    "Operations"  = @("/shared/",                       "/shared/informes_publicos/",    "/marketing/analytics/")
    "Engineering" = @("/it-sistemas/scripts/",          "/it-sistemas/config/",          "/shared/")
    "Executive"   = @("/directivos/estrategia_2026.pdf","/directivos/m&a_targets.xlsx",  "/finanzas/presupuestos/")
    "Default"     = @("/shared/",                       "/shared/plantillas/")
}

$recursosCompartidos = @("/shared/", "/shared/plantillas/", "/shared/informes_publicos/")

$criticidadMap = @{
    "/finanzas/"         = "High"
    "/it-sistemas/"      = "High"
    "/directivos/"       = "High"
    "/recursos-humanos/" = "Medium"
    "/marketing/"        = "Low"
    "/shared/"           = "Low"
}

$opsPorRol = @{
    "Reader"      = @("StorageRead")
    "Contributor" = @("StorageRead", "StorageWrite")
    "Owner"       = @("StorageRead", "StorageWrite", "StorageDelete")
}

$perfilesUsuario = @(
    @{ Tipo = "PowerUser"; Prob = 20; MinOps = 65; MaxOps = 90 }
    @{ Tipo = "Normal";    Prob = 60; MinOps = 38; MaxOps = 55 }
    @{ Tipo = "Pasivo";    Prob = 20; MinOps = 12; MaxOps = 28 }
)

$multDiaSemana = @{ 0=0.04; 1=1.10; 2=1.00; 3=1.00; 4=0.95; 5=0.75; 6=0.04 }

# ----------------------------------------------------------
# SECCIÓN 2: FUNCIONES AUXILIARES
# ----------------------------------------------------------

function Get-PerfilUsuario {
    $r = Get-Random -Min 1 -Max 101; $acum = 0
    foreach ($p in $perfilesUsuario) {
        $acum += $p.Prob
        if ($r -le $acum) { return $p }
    }
    return $perfilesUsuario[1]
}

function Get-DeviceID {
    param([string]$UPN)
    $hash = [Math]::Abs($UPN.GetHashCode() % 9000) + 1000
    return "CORP-DEV-$hash"
}

function Get-NetworkInfo {
    param([string]$Sede, [string]$UPN)
    $octeto = [Math]::Abs($UPN.GetHashCode() % 253) + 2
    $prob = Get-Random -Min 1 -Max 101
    if ($prob -le 85) {
        return @{ IP = "$($sedes[$Sede].CorpSubnet).$octeto"; NetworkType = "Corporate" }
    } elseif ($prob -le 97) {
        return @{ IP = "$($sedes[$Sede].VPNSubnet).$octeto"; NetworkType = "VPN" }
    } else {
        $p1 = Get-Random -Min 80 -Max 220; $p2 = Get-Random -Min 1 -Max 254
        return @{ IP = "$p1.$p2.$(Get-Random -Min 1 -Max 254).$octeto"; NetworkType = "External" }
    }
}

function Get-Criticidad {
    param([string]$Recurso)
    foreach ($key in $criticidadMap.Keys) {
        if ($Recurso -like "*$key*") { return $criticidadMap[$key] }
    }
    return "Low"
}

function Get-RecursoDept {
    param([string]$Dept)
    $prob = Get-Random -Min 1 -Max 101
    if ($prob -le 80) {
        $lista = $contenedoresPorDept[$Dept]
        if (-not $lista) { $lista = $contenedoresPorDept["Default"] }
        return $lista | Get-Random
    }
    return $recursosCompartidos | Get-Random
}

function Get-HoraUTC {
    param([int]$UTCOffset, [string]$TipoUsuario)
    $probFuera = switch ($TipoUsuario) { "PowerUser"{15} "Normal"{5} "Pasivo"{2} default{5} }
    $r = Get-Random -Min 1 -Max 101
    $horaLocal = if ($r -le (100 - $probFuera)) { Get-Random -Min 9 -Max 18 } else { Get-Random -Min 0 -Max 24 }
    return ($horaLocal - $UTCOffset + 24) % 24
}

function Get-RolPorDept {
    param([string]$Dept)
    switch ($Dept) {
        "IT"        { return "Owner" }
        "Finance"   { return "Contributor" }
        "Executive" { return "Owner" }
        default     { return "Reader" }
    }
}

function New-LogLine {
    param($Ts,$UPN,$Dept,$Office,$Country,$Op,$Resource,$Result,$IP,$NetType,$DevID,$UserProfile)
    $crit = Get-Criticidad -Recurso $Resource
    return "$Ts,$UPN,$Dept,$Office,$Country,$Op,$Resource,$Result,$IP,$NetType,$DevID,$crit,$UserProfile"
}

# ----------------------------------------------------------
# SECCIÓN 3: CARGA DE USUARIOS
# ----------------------------------------------------------

$nombreArchivo = "../Data/UserCreateTemplate.csv"
if (-not (Test-Path $nombreArchivo)) {
    Write-Host "ERROR: No se encuentra '$nombreArchivo'." -ForegroundColor Red; return
}
$usuarios = Get-Content $nombreArchivo | Select-Object -Skip 1 | ConvertFrom-Csv
Write-Host "Usuarios cargados: $($usuarios.Count)" -ForegroundColor Green

# ----------------------------------------------------------
# SECCIÓN 4: PRE-ASIGNACIÓN CONSISTENTE POR USUARIO
# Mismo perfil, sede, device y rol en TODOS los días
# ----------------------------------------------------------

$perfilPorUPN = @{}
$sedePorUPN   = @{}
$devicePorUPN = @{}
$rolPorUPN    = @{}
$listaSedes   = $sedes.Keys | Sort-Object

foreach ($u in $usuarios) {
    $upn  = $u."Nombre de usuario [userPrincipalName] Obligatorio"
    $dept = $u."Departamento [department]"
    $hash = [Math]::Abs($upn.GetHashCode())

    $perfilPorUPN[$upn] = Get-PerfilUsuario
    $sedePorUPN[$upn]   = $listaSedes[$hash % $listaSedes.Count]
    $devicePorUPN[$upn] = Get-DeviceID -UPN $upn
    $rolPorUPN[$upn]    = Get-RolPorDept -Dept $dept
}

Write-Host "Perfiles pre-asignados. Iniciando generación de ~400.000 registros..." -ForegroundColor Cyan

# ----------------------------------------------------------
# SECCIÓN 5: GENERACIÓN DEL DATASET
# CAMBIO v3.1: período extendido para ~400k registros
#   Enero completo (2026-01-01 al 2026-01-31)
#   + Febrero parcial (2026-02-01 al 2026-02-11)
#   = 42 días → ~406.000 registros
# Las amenazas están fijadas en 2026-01-05 al 2026-01-25
# y quedan en el centro del período sin ningún solapamiento.
# ----------------------------------------------------------

$rutaLogs = "../Data/logs_normales.csv"
$lineas   = New-Object System.Collections.Generic.List[string]
$lineas.Add("CustomTimestamp,UserPrincipalName,Department,Office,Country,Operation,Resource,Result,IP_Address,NetworkType,Device_ID,Resource_Criticality,UserProfile")

# Generar lista de fechas: enero 1-31 + febrero 1-11
$fechas = @()
foreach ($dia in 1..31) {
    $fechas += "2026-01-$($dia.ToString('00'))"
}
foreach ($dia in 1..11) {
    $fechas += "2026-02-$($dia.ToString('00'))"
}

foreach ($fechaStr in $fechas) {
    $fechaObj = [datetime]::ParseExact($fechaStr, "yyyy-MM-dd", $null)
    $diaSem   = [int]$fechaObj.DayOfWeek
    $multDia  = $multDiaSemana[$diaSem]

    foreach ($u in $usuarios) {
        $upn     = $u."Nombre de usuario [userPrincipalName] Obligatorio"
        $dept    = $u."Departamento [department]"
        $perfil  = $perfilPorUPN[$upn]
        $sede    = $sedePorUPN[$upn]
        $city    = $sedes[$sede].City
        $cc      = $sedes[$sede].CC
        $utcOff  = $sedes[$sede].UTCOffset
        $devID   = $devicePorUPN[$upn]
        $rol     = $rolPorUPN[$upn]
        $opsDisp = $opsPorRol[$rol]

        $volBase  = Get-Random -Min $perfil.MinOps -Max $perfil.MaxOps
        $volFinal = [Math]::Max(1, [int]($volBase * $multDia))

        for ($i = 0; $i -lt $volFinal; $i++) {
            $h       = (Get-HoraUTC -UTCOffset $utcOff -TipoUsuario $perfil.Tipo).ToString('00')
            $m       = (Get-Random -Min 0 -Max 59).ToString('00')
            $s       = (Get-Random -Min 0 -Max 59).ToString('00')
            $ts      = "$fechaStr ${h}:${m}:${s}"
            $op      = $opsDisp | Get-Random
            $rec     = Get-RecursoDept -Dept $dept
            $netInfo = Get-NetworkInfo -Sede $sede -UPN $upn
            $ip      = $netInfo.IP
            $netType = $netInfo.NetworkType

            $tasaErr = switch ($perfil.Tipo) { "PowerUser"{2} "Normal"{3} "Pasivo"{5} default{3} }
            $result  = if ((Get-Random -Min 1 -Max 101) -le $tasaErr) { "Failed" } else { "Success" }

            $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office $city -Country $cc `
                -Op $op -Resource $rec -Result $result -IP $ip -NetType $netType `
                -DevID $devID -UserProfile $perfil.Tipo))
        }
    }

    if ($fechaObj.Day % 5 -eq 0 -or $fechaObj.Day -eq 1) {
        Write-Host "  -> Hasta $fechaStr | Registros: $($lineas.Count - 1)" -ForegroundColor DarkCyan
    }
}

# ----------------------------------------------------------
# SECCIÓN 6: GUARDADO Y VERIFICACIÓN
# ----------------------------------------------------------

$lineas | Out-File $rutaLogs -Encoding utf8
$total = (Import-Csv $rutaLogs).Count

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "   LOGS NORMALES GENERADOS v3.1"         -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Archivo          : $rutaLogs"             -ForegroundColor Yellow
Write-Host "Total registros  : $total"                -ForegroundColor White
Write-Host "Período          : 2026-01-01 al 2026-02-11 (42 días)" -ForegroundColor Cyan
Write-Host "Esquema maestro  : 13 columnas"           -ForegroundColor Cyan