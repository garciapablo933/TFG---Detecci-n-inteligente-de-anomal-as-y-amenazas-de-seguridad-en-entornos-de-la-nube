# ==========================================================
# SCRIPT DE GENERACIÓN DE DATASET DE AMENAZAS
# Version 5.2 - 10 instancias x 5 amenazas = 50 usuarios
# ----------------------------------------------------------
# CAMBIOS v5.2 vs v5.1:
#   - BruteForce Fase2: Min8 Max14 (~11/dia/pais) — escalada visible
#     por encima del ruido normal (usuarios legítimos: 1-3 Failed/dia)
#   - BruteForce Fase3: Min14 Max22 (~18/dia/pais) — pico claro,
#     IP fija repetida (IOC botnet), progresión correcta F1<F2<F3
#   - Con 406k normales (logs_normales x2): ratio ~4.94%% maliciosos
#
# DISEÑO DE IOCs POR AMENAZA:
#   BruteForce APT       -> IsFailedOrDenied alto + IsExternalNetwork
#                           + escalada progresiva de volumen por dia
#   Exfiltración Insider -> Hour 1-5am + IsUnknownDevice + DailyOpsVolume alto
#                           + IP de sede distinta a la del usuario
#   GeoAnomaly VPN       -> UniqueCountriesPerDay alto + IsExternalNetwork
#                           + pais diferente cada dia (rotacion sistematica)
#   Phishing Takeover    -> UniqueCountriesPerDay=2 mismo UPN mismo dia
#                           + IsUnknownDevice atacante vs CORP-DEV usuario real
#   Ransomware           -> UniqueContainersPerDay=6 + DailyOpsVolume extremo
#                           + IsWriteOrDelete masivo + beacons C2 External
#
# ESQUEMA ground_truth_eventos.csv (8 columnas):
#   CustomTimestamp, UserPrincipalName, ThreatType, ThreatInstance,
#   Department, Country, Operation, Result
#
# ESQUEMA logs_amenazas.csv (13 columnas - IDÉNTICO al de logs normales):
#   CustomTimestamp, UserPrincipalName, Department, Office,
#   Country, Operation, Resource, Result, IP_Address,
#   NetworkType, Device_ID, Resource_Criticality, UserProfile
# ----------------------------------------------------------
# CSV base requerido: UserCreateTemplate.csv (300 usuarios)
# Outputs:
#   -> logs_amenazas.csv         -> se mezcla con logs_normales.csv (x2)
#   -> ground_truth_eventos.csv  -> SOLO para evaluar el modelo, NUNCA entrenar
# ==========================================================

# ----------------------------------------------------------
# SECCI?N 1: CONFIGURACI?N GLOBAL
# ----------------------------------------------------------

$sedes = @{
    "Espana"      = @{ UTCOffset = 1;  CorpSubnet = "10.1.1"; VPNSubnet = "172.16.1"; City = "Madrid";      CC = "ES" }
    "Alemania"    = @{ UTCOffset = 1;  CorpSubnet = "10.2.1"; VPNSubnet = "172.16.2"; City = "Berlin";      CC = "DE" }
    "Reino Unido" = @{ UTCOffset = 0;  CorpSubnet = "10.3.1"; VPNSubnet = "172.16.3"; City = "London";      CC = "GB" }
    "Italia"      = @{ UTCOffset = 1;  CorpSubnet = "10.4.1"; VPNSubnet = "172.16.4"; City = "Milan";       CC = "IT" }
    "Polonia"     = @{ UTCOffset = 1;  CorpSubnet = "10.5.1"; VPNSubnet = "172.16.5"; City = "Warsaw";      CC = "PL" }
    "EEUU-Este"   = @{ UTCOffset = -5; CorpSubnet = "10.6.1"; VPNSubnet = "172.16.6"; City = "New York";    CC = "US" }
    "EEUU-Oeste"  = @{ UTCOffset = -8; CorpSubnet = "10.7.1"; VPNSubnet = "172.16.7"; City = "Los Angeles"; CC = "US" }
}

$ipAtacantes = @{
    "KP"  = "180"; "RU" = "95";  "CN" = "103"
    "IR"  = "5";   "BR" = "177"; "NG" = "197"; "TOR" = "185"
}

$contenedores = @{
    "IT"        = @("/it-sistemas/config/",           "/it-sistemas/scripts/",        "/it-sistemas/backups/")
    "Finance"   = @("/finanzas/facturas/",             "/finanzas/presupuestos/",      "/finanzas/nominas/")
    "HR"        = @("/recursos-humanos/contratos/",    "/recursos-humanos/nominas/",   "/recursos-humanos/expedientes/")
    "Marketing" = @("/marketing/campanas/",            "/marketing/assets/",           "/marketing/analytics/")
    "Executive" = @("/directivos/estrategia_2026.pdf", "/directivos/m&a_targets.xlsx", "/directivos/board_minutes.docx")
    "Shared"    = @("/shared/",                        "/shared/plantillas/",          "/shared/informes_publicos/")
}

$deptMap = @{
    "it-sistemas"     = "IT"
    "finanzas"        = "Finance"
    "marketing"       = "Marketing"
    "recursos-humanos"= "HR"
    "directivos"      = "Executive"
    "shared"          = "Shared"
}

$backups = @(
    "/it-sistemas/backups/database_full_backup.bak",
    "/it-sistemas/backups/db_usuarios_2025.bak",
    "/it-sistemas/backups/app_backup_2026.tar.gz"
)

$criticidadMap = @{
    "/finanzas/"         = "High"
    "/it-sistemas/"      = "High"
    "/directivos/"       = "High"
    "/recursos-humanos/" = "Medium"
    "/marketing/"        = "Low"
    "/shared/"           = "Low"
}

$vpnRotacion   = @("KP","RU","CN","IR","BR","NG","TOR","KP","RU","CN","IR","BR","NG","TOR","KP","RU","CN","IR","BR","TOR")
$listaSedes    = $sedes.Keys | Sort-Object
$extsCrypt     = @(".crypt",".locked",".enc",".crypted")
$nombresBase   = @("documento","informe","contrato","nomina","presupuesto","estrategia","backup","config","base_datos","expediente")
$c2Paises      = @("KP","IR","TOR")

$aptGrupos = @(
    @("KP","RU","CN"), @("KP","IR","CN"), @("RU","CN","NG"),
    @("KP","RU","IR"), @("CN","IR","TOR"),@("KP","NG","TOR"),
    @("RU","IR","BR"), @("CN","KP","BR"), @("IR","TOR","NG"),
    @("KP","RU","TOR")
)

# ----------------------------------------------------------
# SECCI?N 2: FUNCIONES AUXILIARES
# ----------------------------------------------------------

function Get-Criticidad { param([string]$R)
    foreach ($k in $criticidadMap.Keys) { if ($R -like "*$k*") { return $criticidadMap[$k] } }
    return "Low"
}

function Get-IPAtacante { param([string]$CC)
    $pfx = $ipAtacantes[$CC]
    return "$pfx.$(Get-Random -Min 1 -Max 255).$(Get-Random -Min 1 -Max 255).$(Get-Random -Min 1 -Max 255)"
}

function Get-IPCorp { param([string]$Sede, [string]$Salt = "x")
    $oct = [Math]::Abs(($Sede + $Salt).GetHashCode() % 253) + 2
    return "$($sedes[$Sede].CorpSubnet).$oct"
}

function Get-DeviceID { param([string]$UPN, [bool]$EsAtacante = $false)
    if ($EsAtacante) { return "UNKNOWN-BYOD-$(Get-Random -Min 1000 -Max 9999)" }
    return "CORP-DEV-$([Math]::Abs($UPN.GetHashCode() % 9000) + 1000)"
}

function Get-TS { param([string]$Fecha, [int]$HMin, [int]$HMax)
    $h = (Get-Random -Min $HMin -Max $HMax).ToString('00')
    $m = (Get-Random -Min 0 -Max 59).ToString('00')
    $s = (Get-Random -Min 0 -Max 59).ToString('00')
    return "$Fecha ${h}:${m}:${s}"
}

function Get-ContKey { param([string]$Dept)
    if ($deptMap.ContainsKey($Dept)) { return $deptMap[$Dept] }
    return "Shared"
}

function Get-SedeDeUsuario { param([string]$UPN)
    return $listaSedes[[Math]::Abs($UPN.GetHashCode()) % $listaSedes.Count]
}

function Get-SedeDistinta { param([string]$SedeActual)
    $otras = $listaSedes | Where-Object { $_ -ne $SedeActual }
    return $otras | Get-Random
}

# ESQUEMA MAESTRO - 13 columnas
function New-LogLine {
    param($Ts,$UPN,$Dept,$Office,$Country,$Op,$Resource,$Result,$IP,$NetType,$DevID,$UserProfile)
    $crit = Get-Criticidad -R $Resource
    return "$Ts,$UPN,$Dept,$Office,$Country,$Op,$Resource,$Result,$IP,$NetType,$DevID,$crit,$UserProfile"
}

# NUEVA FUNCI?N: anade evento al ground truth de eventos
# Solo se llama para eventos MALICIOSOS, nunca para normales
function Add-GT {
    param($Ts, $UPN, $ThreatType, $ThreatInstance, $Dept, $Country, $Op, $Result)
    $script:groundTruth.Add("$Ts,$UPN,$ThreatType,$ThreatInstance,$Dept,$Country,$Op,$Result")
}

# Bloque de comportamiento NORMAL - NO se registra en ground truth
function Add-Normales {
    param($UPN, $Dept, $DiaIni, $DiaFin, $Lineas)
    $sede   = Get-SedeDeUsuario -UPN $UPN
    $ip     = Get-IPCorp -Sede $sede -Salt $UPN
    $dev    = Get-DeviceID -UPN $UPN
    $city   = $sedes[$sede].City
    $cc     = $sedes[$sede].CC
    $ckey   = Get-ContKey -Dept $Dept

    foreach ($dia in $DiaIni..$DiaFin) {
        $fecha = "2026-01-$($dia.ToString('00'))"
        $nOps  = Get-Random -Min 25 -Max 40
        for ($i = 0; $i -lt $nOps; $i++) {
            $ts  = Get-TS -Fecha $fecha -HMin 9 -HMax 18
            $rec = ($contenedores[$ckey] | Get-Random)
            $Lineas.Add((New-LogLine -Ts $ts -UPN $UPN -Dept $Dept -Office $city -Country $cc `
                -Op "StorageRead" -Resource $rec -Result "Success" `
                -IP $ip -NetType "Corporate" -DevID $dev -UserProfile "Normal"))
            # NOTA: NO se llama a Add-GT aqui - estos eventos son normales
        }
    }
}

# ----------------------------------------------------------
# SECCI?N 3: CARGA DE USUARIOS
# ----------------------------------------------------------

$nombreArchivo = "../Data/UserCreateTemplate.csv"
if (-not (Test-Path $nombreArchivo)) {
    Write-Host "ERROR: No se encuentra '$nombreArchivo'." -ForegroundColor Red
    return
}

$usuarios   = Get-Content $nombreArchivo | Select-Object -Skip 1 | ConvertFrom-Csv
Write-Host "Usuarios cargados: $($usuarios.Count)" -ForegroundColor Cyan

$rutaAmenazas    = "../Data/logs_amenazas.csv"
$rutaGroundTruth = "../Data/ground_truth_eventos.csv"

$lineas      = New-Object System.Collections.Generic.List[string]
$groundTruth = New-Object System.Collections.Generic.List[string]

$lineas.Add("CustomTimestamp,UserPrincipalName,Department,Office,Country,Operation,Resource,Result,IP_Address,NetworkType,Device_ID,Resource_Criticality,UserProfile")
$groundTruth.Add("CustomTimestamp,UserPrincipalName,ThreatType,ThreatInstance,Department,Country,Operation,Result")

Write-Host ""
Write-Host "+============================================================+" -ForegroundColor DarkRed
Write-Host "|  INYECTANDO AMENAZAS v5.2 - ground truth A NIVEL EVENTO  |" -ForegroundColor DarkRed
Write-Host "|  50 usuarios / ~21k maliciosos / ~4.94%% sobre 406k norm  |" -ForegroundColor DarkRed
Write-Host "+============================================================+" -ForegroundColor DarkRed

$poolUsuarios   = $usuarios | Get-Random -Count $usuarios.Count
$idxPool        = 0

function Get-SiguienteUsuario {
    $u = $poolUsuarios[$script:idxPool]
    $script:idxPool++
    return $u
}

# ----------------------------------------------------------
# AMENAZA 1: FUERZA BRUTA APT - 10 instancias
# ----------------------------------------------------------
# Eventos maliciosos: TODOS los intentos desde IPs atacantes (Failed/Success)
# Los eventos normales de Add-Normales NO entran en ground truth
# ----------------------------------------------------------
Write-Host "`n[1/5] Fuerza Bruta APT (10 instancias)..." -ForegroundColor Red

for ($inst = 0; $inst -lt 10; $inst++) {
    $victima    = Get-SiguienteUsuario
    $upn        = $victima."Nombre de usuario [userPrincipalName] Obligatorio"
    $dept       = $victima."Departamento [department]"
    $paises     = $aptGrupos[$inst]
    $diaBase    = 5 + ($inst % 7)
    $diaComp    = $diaBase + 11
    $instID     = "BF_$(($inst+1).ToString('00'))"

    # Fase 1: Reconocimiento - MALICIOSO -> entra en ground truth
    foreach ($dia in $diaBase..($diaBase+2)) {
        $fecha = "2026-01-$($dia.ToString('00'))"
        foreach ($pais in $paises) {
            $n = Get-Random -Min 2 -Max 7
            for ($i = 0; $i -lt $n; $i++) {
                $ts  = Get-TS -Fecha $fecha -HMin 9 -HMax 22
                $ip  = Get-IPAtacante -CC $pais
                $dev = Get-DeviceID -UPN $upn -EsAtacante $true
                $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office "Unknown" -Country $pais `
                    -Op "StorageRead" -Resource "/directivos/estrategia_2026.pdf" -Result "Failed" `
                    -IP $ip -NetType "External" -DevID $dev -UserProfile "Normal"))
                Add-GT -Ts $ts -UPN $upn -ThreatType "BruteForce_APT" -ThreatInstance $instID `
                    -Dept $dept -Country $pais -Op "StorageRead" -Result "Failed"
            }
        }
    }

    # Fase 2: Escalada - MALICIOSO
    # Min 8 Max 14: ~11/dia/pais -> claramente por encima del ruido normal (1-3 Failed/dia)
    foreach ($dia in ($diaBase+3)..($diaBase+7)) {
        $fecha = "2026-01-$($dia.ToString('00'))"
        foreach ($pais in $paises) {
            $n = Get-Random -Min 8 -Max 14
            for ($i = 0; $i -lt $n; $i++) {
                $ts  = Get-TS -Fecha $fecha -HMin 0 -HMax 23
                $ip  = Get-IPAtacante -CC $pais
                $dev = Get-DeviceID -UPN $upn -EsAtacante $true
                $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office "Unknown" -Country $pais `
                    -Op "StorageRead" -Resource "/directivos/estrategia_2026.pdf" -Result "Failed" `
                    -IP $ip -NetType "External" -DevID $dev -UserProfile "Normal"))
                Add-GT -Ts $ts -UPN $upn -ThreatType "BruteForce_APT" -ThreatInstance $instID `
                    -Dept $dept -Country $pais -Op "StorageRead" -Result "Failed"
            }
        }
    }

    # Fase 3: Pico masivo - MALICIOSO
    # Min 14 Max 22: ~18/dia/pais -> pico claro, IP fija repetida (IOC botnet)
    foreach ($dia in ($diaBase+8)..($diaBase+10)) {
        $fecha = "2026-01-$($dia.ToString('00'))"
        foreach ($pais in $paises) {
            $ipFija = Get-IPAtacante -CC $pais
            $n = Get-Random -Min 14 -Max 22
            for ($i = 0; $i -lt $n; $i++) {
                $ts  = Get-TS -Fecha $fecha -HMin 0 -HMax 23
                $dev = Get-DeviceID -UPN $upn -EsAtacante $true
                $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office "Unknown" -Country $pais `
                    -Op "StorageRead" -Resource "/directivos/estrategia_2026.pdf" -Result "Failed" `
                    -IP $ipFija -NetType "External" -DevID $dev -UserProfile "Normal"))
                Add-GT -Ts $ts -UPN $upn -ThreatType "BruteForce_APT" -ThreatInstance $instID `
                    -Dept $dept -Country $pais -Op "StorageRead" -Result "Failed"
            }
        }
    }

    # Fase 4: Compromiso exitoso + post-exfiltracion - MALICIOSO
    if ($diaComp -le 25) {
        $fechaComp = "2026-01-$($diaComp.ToString('00'))"
        $paisComp  = $paises[0]
        $ipComp    = Get-IPAtacante -CC $paisComp
        $devComp   = Get-DeviceID -UPN $upn -EsAtacante $true

        $tsLogin = "$fechaComp 03:$(Get-Random -Min 10 -Max 59):$(Get-Random -Min 10 -Max 59)"
        $lineas.Add((New-LogLine -Ts $tsLogin -UPN $upn -Dept $dept -Office "Unknown" -Country $paisComp `
            -Op "StorageRead" -Resource "/directivos/estrategia_2026.pdf" -Result "Success" `
            -IP $ipComp -NetType "External" -DevID $devComp -UserProfile "Normal"))
        Add-GT -Ts $tsLogin -UPN $upn -ThreatType "BruteForce_APT" -ThreatInstance $instID `
            -Dept $dept -Country $paisComp -Op "StorageRead" -Result "Success"

        foreach ($rec in @("/directivos/m&a_targets.xlsx","/finanzas/presupuestos/","/it-sistemas/config/")) {
            for ($i = 0; $i -lt (Get-Random -Min 5 -Max 15); $i++) {
                $ts = Get-TS -Fecha $fechaComp -HMin 3 -HMax 5
                $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office "Unknown" -Country $paisComp `
                    -Op "StorageRead" -Resource $rec -Result "Success" `
                    -IP $ipComp -NetType "External" -DevID $devComp -UserProfile "Normal"))
                Add-GT -Ts $ts -UPN $upn -ThreatType "BruteForce_APT" -ThreatInstance $instID `
                    -Dept $dept -Country $paisComp -Op "StorageRead" -Result "Success"
            }
        }
    }
}
Write-Host "   -> BF APT completado" -ForegroundColor DarkYellow

# ----------------------------------------------------------
# AMENAZA 2: EXFILTRACI?N NOCTURNA - 10 instancias
# ----------------------------------------------------------
# Eventos maliciosos: Fase 2 (reconocimiento nocturno), Fase 3 (exfiltracion), Fase 4 (lateral)
# Fase 1 (normal de dia desde sede real) NO entra en ground truth
# ----------------------------------------------------------
Write-Host "[2/5] Exfiltracion Nocturna (10 instancias)..." -ForegroundColor Red

for ($inst = 0; $inst -lt 10; $inst++) {
    $insider   = Get-SiguienteUsuario
    $upn       = $insider."Nombre de usuario [userPrincipalName] Obligatorio"
    $dept      = $insider."Departamento [department]"
    $ckey      = Get-ContKey -Dept $dept
    $sedeReal  = Get-SedeDeUsuario -UPN $upn
    $sedePivot = Get-SedeDistinta -SedeActual $sedeReal
    $instID    = "EX_$(($inst+1).ToString('00'))"

    $ipReal    = Get-IPCorp -Sede $sedeReal  -Salt $upn
    $ipPivot   = Get-IPCorp -Sede $sedePivot -Salt "$upn-pivot"
    $devNormal = Get-DeviceID -UPN $upn
    $devByod   = Get-DeviceID -UPN $upn -EsAtacante $true
    $cityReal  = $sedes[$sedeReal].City;  $ccReal  = $sedes[$sedeReal].CC
    $cityPivot = $sedes[$sedePivot].City; $ccPivot = $sedes[$sedePivot].CC

    $diaBase   = 5 + ($inst % 8)

    # Fase 2: Reconocimiento nocturno - MALICIOSO (hora anomala, aunque IP propia)
    foreach ($dia in ($diaBase+4)..($diaBase+6)) {
        $fecha = "2026-01-$($dia.ToString('00'))"
        for ($i = 0; $i -lt (Get-Random -Min 8 -Max 15); $i++) {
            $ts = Get-TS -Fecha $fecha -HMin 22 -HMax 23
            $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office $cityReal -Country $ccReal `
                -Op "StorageRead" -Resource ($contenedores["IT"] | Get-Random) -Result "Success" `
                -IP $ipReal -NetType "Corporate" -DevID $devNormal -UserProfile "Normal"))
            Add-GT -Ts $ts -UPN $upn -ThreatType "Exfiltration_Insider" -ThreatInstance $instID `
                -Dept $dept -Country $ccReal -Op "StorageRead" -Result "Success"
        }
    }

    # Fase 3: Exfiltracion masiva - MALICIOSO
    foreach ($dia in ($diaBase+7)..($diaBase+13)) {
        if ($dia -gt 25) { break }
        $fecha = "2026-01-$($dia.ToString('00'))"
        $n     = Get-Random -Min 50 -Max 90
        for ($i = 0; $i -lt $n; $i++) {
            $ts      = Get-TS -Fecha $fecha -HMin 1 -HMax 5
            $archivo = $backups | Get-Random
            $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office $cityPivot -Country $ccPivot `
                -Op "StorageRead" -Resource $archivo -Result "Success" `
                -IP $ipPivot -NetType "Corporate" -DevID $devByod -UserProfile "Normal"))
            Add-GT -Ts $ts -UPN $upn -ThreatType "Exfiltration_Insider" -ThreatInstance $instID `
                -Dept $dept -Country $ccPivot -Op "StorageRead" -Result "Success"
        }
    }

    # Fase 4: Movimiento lateral - MALICIOSO
    $diaLat = [Math]::Min($diaBase + 14, 24)
    foreach ($dia in $diaLat..([Math]::Min($diaLat+1, 25))) {
        $fecha = "2026-01-$($dia.ToString('00'))"
        foreach ($deptObj in @("Executive","Finance")) {
            for ($i = 0; $i -lt (Get-Random -Min 15 -Max 30); $i++) {
                $ts  = Get-TS -Fecha $fecha -HMin 2 -HMax 6
                $rec = ($contenedores[$deptObj] | Get-Random)
                $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office $cityPivot -Country $ccPivot `
                    -Op "StorageRead" -Resource $rec -Result "Success" `
                    -IP $ipPivot -NetType "Corporate" -DevID $devByod -UserProfile "Normal"))
                Add-GT -Ts $ts -UPN $upn -ThreatType "Exfiltration_Insider" -ThreatInstance $instID `
                    -Dept $dept -Country $ccPivot -Op "StorageRead" -Result "Success"
            }
        }
    }
}
Write-Host "   -> Exfiltracion Insider completada" -ForegroundColor DarkYellow

# ----------------------------------------------------------
# AMENAZA 3: GEO-ANOMAL?A CON VPN ROTATION - 10 instancias
# ----------------------------------------------------------
# Todos los accesos desde IPs externas rotando paises son maliciosos
# ----------------------------------------------------------
Write-Host "[3/5] Geo-Anomalia VPN Rotation (10 instancias)..." -ForegroundColor Red

for ($inst = 0; $inst -lt 10; $inst++) {
    $victima  = Get-SiguienteUsuario
    $upn      = $victima."Nombre de usuario [userPrincipalName] Obligatorio"
    $dept     = $victima."Departamento [department]"
    $diaBase  = 5 + ($inst % 8)
    $rotOffset= $inst * 3
    $diaIdx   = $rotOffset
    $instID   = "GEO_$(($inst+1).ToString('00'))"

    # Fase 1: Reconocimiento - MALICIOSO
    foreach ($dia in $diaBase..($diaBase+3)) {
        $fecha   = "2026-01-$($dia.ToString('00'))"
        $paisHoy = $vpnRotacion[$diaIdx % $vpnRotacion.Count]; $diaIdx++
        for ($i = 0; $i -lt (Get-Random -Min 3 -Max 9); $i++) {
            $ts  = Get-TS -Fecha $fecha -HMin 6 -HMax 20
            $ip  = Get-IPAtacante -CC $paisHoy
            $dev = Get-DeviceID -UPN $upn -EsAtacante $true
            $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office "Unknown" -Country $paisHoy `
                -Op "StorageRead" -Resource ($contenedores["Shared"] | Get-Random) -Result "Success" `
                -IP $ip -NetType "External" -DevID $dev -UserProfile "Normal"))
            Add-GT -Ts $ts -UPN $upn -ThreatType "GeoAnomaly_VPNRotation" -ThreatInstance $instID `
                -Dept $dept -Country $paisHoy -Op "StorageRead" -Result "Success"
        }
    }

    # Fase 2: Escalada - MALICIOSO
    foreach ($dia in ($diaBase+4)..($diaBase+9)) {
        if ($dia -gt 25) { break }
        $fecha   = "2026-01-$($dia.ToString('00'))"
        $paisHoy = $vpnRotacion[$diaIdx % $vpnRotacion.Count]; $diaIdx++
        $ip      = Get-IPAtacante -CC $paisHoy
        for ($i = 0; $i -lt (Get-Random -Min 15 -Max 40); $i++) {
            $ts  = Get-TS -Fecha $fecha -HMin 0 -HMax 23
            $dev = Get-DeviceID -UPN $upn -EsAtacante $true
            $rec = ($contenedores["IT"] | Get-Random)
            $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office "Unknown" -Country $paisHoy `
                -Op "StorageRead" -Resource $rec -Result "Denied" `
                -IP $ip -NetType "External" -DevID $dev -UserProfile "Normal"))
            Add-GT -Ts $ts -UPN $upn -ThreatType "GeoAnomaly_VPNRotation" -ThreatInstance $instID `
                -Dept $dept -Country $paisHoy -Op "StorageRead" -Result "Denied"
        }
    }

    # Fase 3: Persistence - MALICIOSO
    foreach ($dia in ($diaBase+10)..([Math]::Min($diaBase+15, 25))) {
        $fecha   = "2026-01-$($dia.ToString('00'))"
        $paisHoy = $vpnRotacion[$diaIdx % $vpnRotacion.Count]; $diaIdx++
        $ip      = Get-IPAtacante -CC $paisHoy
        for ($i = 0; $i -lt (Get-Random -Min 5 -Max 12); $i++) {
            $ts  = Get-TS -Fecha $fecha -HMin 0 -HMax 23
            $dev = Get-DeviceID -UPN $upn -EsAtacante $true
            $prob = Get-Random -Min 1 -Max 101
            if ($prob -le 40) { $rec = ($contenedores["Shared"] | Get-Random); $res = "Success" }
            else               { $rec = ($contenedores["Finance"] | Get-Random); $res = "Denied" }
            $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office "Unknown" -Country $paisHoy `
                -Op "StorageRead" -Resource $rec -Result $res `
                -IP $ip -NetType "External" -DevID $dev -UserProfile "Normal"))
            Add-GT -Ts $ts -UPN $upn -ThreatType "GeoAnomaly_VPNRotation" -ThreatInstance $instID `
                -Dept $dept -Country $paisHoy -Op "StorageRead" -Result $res
        }
    }
}
Write-Host "   -> VPN Rotation completada" -ForegroundColor DarkYellow

# ----------------------------------------------------------
# AMENAZA 4: PHISHING / ACCOUNT TAKEOVER - 10 instancias
# ----------------------------------------------------------
# Malicioso: todos los accesos del ATACANTE (devAtk, ipAtk, cityAtk)
# NO malicioso: accesos del usuario real (devReal, ipReal, cityReal) en Fase 3
# ----------------------------------------------------------
Write-Host "[4/5] Phishing / Account Takeover (10 instancias)..." -ForegroundColor Red

$sedesAtacantes = @("Reino Unido","Alemania","Italia","Polonia","EEUU-Este","EEUU-Oeste","Espana","Reino Unido","Alemania","Italia")

for ($inst = 0; $inst -lt 10; $inst++) {
    $victima     = Get-SiguienteUsuario
    $upn         = $victima."Nombre de usuario [userPrincipalName] Obligatorio"
    $dept        = $victima."Departamento [department]"
    $ckey        = Get-ContKey -Dept $dept
    $sedeReal    = Get-SedeDeUsuario -UPN $upn
    $sedeAtk     = $sedesAtacantes[$inst]
    if ($sedeAtk -eq $sedeReal) { $sedeAtk = ($listaSedes | Where-Object { $_ -ne $sedeReal } | Select-Object -First 1) }
    $instID      = "PH_$(($inst+1).ToString('00'))"

    $ipReal    = Get-IPCorp -Sede $sedeReal -Salt $upn
    $ipAtk     = Get-IPCorp -Sede $sedeAtk  -Salt "$upn-atk$inst"
    $devReal   = Get-DeviceID -UPN $upn
    $devAtk    = Get-DeviceID -UPN $upn -EsAtacante $true
    $cityReal  = $sedes[$sedeReal].City; $ccReal  = $sedes[$sedeReal].CC
    $cityAtk   = $sedes[$sedeAtk].City;  $ccAtk   = $sedes[$sedeAtk].CC
    $diaBase   = 5 + ($inst % 8)

    # Fase 2: Primer acceso del atacante - MALICIOSO
    $fechaPH = "2026-01-$((($diaBase+3).ToString('00')))"
    for ($i = 0; $i -lt (Get-Random -Min 3 -Max 8); $i++) {
        $ts = Get-TS -Fecha $fechaPH -HMin 9 -HMax 17
        $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office $cityAtk -Country $ccAtk `
            -Op "StorageRead" -Resource ($contenedores[$ckey] | Get-Random) -Result "Success" `
            -IP $ipAtk -NetType "Corporate" -DevID $devAtk -UserProfile "Normal"))
        Add-GT -Ts $ts -UPN $upn -ThreatType "Phishing_AccountTakeover" -ThreatInstance $instID `
            -Dept $dept -Country $ccAtk -Op "StorageRead" -Result "Success"
    }

    # Fase 3: Acceso simultaneo - solo el atacante es MALICIOSO
    foreach ($dia in ($diaBase+4)..($diaBase+9)) {
        if ($dia -gt 25) { break }
        $fecha = "2026-01-$($dia.ToString('00'))"

        # Usuario real - NO malicioso
        for ($i = 0; $i -lt (Get-Random -Min 10 -Max 20); $i++) {
            $ts  = Get-TS -Fecha $fecha -HMin 9 -HMax 17
            $rec = ($contenedores[$ckey] | Get-Random)
            $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office $cityReal -Country $ccReal `
                -Op "StorageRead" -Resource $rec -Result "Success" `
                -IP $ipReal -NetType "Corporate" -DevID $devReal -UserProfile "Normal"))
            # NO Add-GT
        }

        # Atacante - MALICIOSO
        for ($i = 0; $i -lt (Get-Random -Min 15 -Max 30); $i++) {
            $ts  = Get-TS -Fecha $fecha -HMin 9 -HMax 17
            $rec = ($contenedores["Executive"] | Get-Random)
            $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office $cityAtk -Country $ccAtk `
                -Op "StorageRead" -Resource $rec -Result "Success" `
                -IP $ipAtk -NetType "Corporate" -DevID $devAtk -UserProfile "Normal"))
            Add-GT -Ts $ts -UPN $upn -ThreatType "Phishing_AccountTakeover" -ThreatInstance $instID `
                -Dept $dept -Country $ccAtk -Op "StorageRead" -Result "Success"
        }
    }

    # Fase 4: Movimiento lateral del atacante - MALICIOSO
    foreach ($dia in ($diaBase+10)..([Math]::Min($diaBase+13, 25))) {
        $fecha = "2026-01-$($dia.ToString('00'))"
        foreach ($deptObj in @("Finance","IT")) {
            for ($i = 0; $i -lt (Get-Random -Min 10 -Max 25); $i++) {
                $ts  = Get-TS -Fecha $fecha -HMin 9 -HMax 18
                $rec = ($contenedores[$deptObj] | Get-Random)
                $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office $cityAtk -Country $ccAtk `
                    -Op "StorageRead" -Resource $rec -Result "Success" `
                    -IP $ipAtk -NetType "Corporate" -DevID $devAtk -UserProfile "Normal"))
                Add-GT -Ts $ts -UPN $upn -ThreatType "Phishing_AccountTakeover" -ThreatInstance $instID `
                    -Dept $dept -Country $ccAtk -Op "StorageRead" -Result "Success"
            }
        }
    }
}
Write-Host "   -> Phishing Takeover completado" -ForegroundColor DarkYellow

# ----------------------------------------------------------
# AMENAZA 5: RANSOMWARE - 10 instancias
# ----------------------------------------------------------
# Malicioso: beacons C2, cifrado masivo (StorageWrite .crypt), borrado backups
# NO malicioso: reconocimiento masivo con IP propia (Fase 2 StorageRead) y lateral (Fase 3)
# NOTA DISE?O: el reconocimiento/lateral es ambiguo (IP corp, equipo propio) -> normal
#              El salto claro es el cifrado en masa y el C2 externo
# ----------------------------------------------------------
Write-Host "[5/5] Ransomware (10 instancias)..." -ForegroundColor Red

for ($inst = 0; $inst -lt 10; $inst++) {
    $infectado = Get-SiguienteUsuario
    $upn       = $infectado."Nombre de usuario [userPrincipalName] Obligatorio"
    $dept      = $infectado."Departamento [department]"
    $ckey      = Get-ContKey -Dept $dept
    $sede      = Get-SedeDeUsuario -UPN $upn
    $ip        = Get-IPCorp -Sede $sede -Salt $upn
    $dev       = Get-DeviceID -UPN $upn
    $city      = $sedes[$sede].City
    $cc        = $sedes[$sede].CC
    $diaBase   = 5 + ($inst % 7)
    $diaCifrado= [Math]::Min($diaBase + 11, 24)
    $diaBorrado= [Math]::Min($diaCifrado + 1, 25)
    $instID    = "RW_$(($inst+1).ToString('00'))"

    $c2Inst = @($c2Paises[$inst % $c2Paises.Count], $c2Paises[($inst+1) % $c2Paises.Count])

    # Fase 2: Beacons C2 - MALICIOSO (equipo corporativo conecta a IPs externas sospechosas)
    foreach ($dia in ($diaBase+3)..($diaBase+5)) {
        $fecha = "2026-01-$($dia.ToString('00'))"
        foreach ($c2cc in $c2Inst) {
            for ($i = 0; $i -lt (Get-Random -Min 4 -Max 10); $i++) {
                $ts   = Get-TS -Fecha $fecha -HMin 10 -HMax 22
                $ipC2 = Get-IPAtacante -CC $c2cc
                $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office $city -Country $c2cc `
                    -Op "StorageRead" -Resource "/shared/" -Result "Failed" `
                    -IP $ipC2 -NetType "External" -DevID $dev -UserProfile "Normal"))
                Add-GT -Ts $ts -UPN $upn -ThreatType "Ransomware" -ThreatInstance $instID `
                    -Dept $dept -Country $c2cc -Op "StorageRead" -Result "Failed"
            }
        }
    }

    # Fase 4: Cifrado masivo - MALICIOSO (StorageWrite en masa de archivos .crypt en <30 min)
    if ($diaCifrado -le 25) {
        $fechaCifrado = "2026-01-$($diaCifrado.ToString('00'))"
        foreach ($deptObj in $contenedores.Keys) {
            $contObj = ($contenedores[$deptObj] | Get-Random)
            $nArchivos = Get-Random -Min 80 -Max 150
            for ($i = 1; $i -le $nArchivos; $i++) {
                $ext    = $extsCrypt | Get-Random
                $nombre = "$($nombresBase | Get-Random)_$i$ext"
                $m      = (Get-Random -Min 0 -Max 30).ToString('00')
                $s      = (Get-Random -Min 0 -Max 59).ToString('00')
                $ts     = "$fechaCifrado 09:${m}:${s}"
                $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office $city -Country $cc `
                    -Op "StorageWrite" -Resource "$contObj$nombre" -Result "Success" `
                    -IP $ip -NetType "Corporate" -DevID $dev -UserProfile "Normal"))
                Add-GT -Ts $ts -UPN $upn -ThreatType "Ransomware" -ThreatInstance $instID `
                    -Dept $dept -Country $cc -Op "StorageWrite" -Result "Success"
            }
        }

        # Fase 5: Borrado de backups - MALICIOSO
        if ($diaBorrado -le 25) {
            $fechaBorrado = "2026-01-$($diaBorrado.ToString('00'))"
            foreach ($bk in $backups) {
                for ($i = 0; $i -lt (Get-Random -Min 3 -Max 8); $i++) {
                    $ts  = Get-TS -Fecha $fechaBorrado -HMin 9 -HMax 10
                    $res = if ((Get-Random -Min 1 -Max 101) -le 60) { "Success" } else { "Denied" }
                    $lineas.Add((New-LogLine -Ts $ts -UPN $upn -Dept $dept -Office $city -Country $cc `
                        -Op "StorageDelete" -Resource $bk -Result $res `
                        -IP $ip -NetType "Corporate" -DevID $dev -UserProfile "Normal"))
                    Add-GT -Ts $ts -UPN $upn -ThreatType "Ransomware" -ThreatInstance $instID `
                        -Dept $dept -Country $cc -Op "StorageDelete" -Result $res
                }
            }
        }
    }
}
Write-Host "   -> Ransomware completado" -ForegroundColor DarkYellow

# ----------------------------------------------------------
# SECCI?N 4: GUARDADO DE ARCHIVOS
# ----------------------------------------------------------

$lineas      | Out-File -FilePath $rutaAmenazas    -Encoding utf8
$groundTruth | Out-File -FilePath $rutaGroundTruth -Encoding utf8

$totalAmenazas = (Import-Csv $rutaAmenazas).Count
$totalGT       = (Import-Csv $rutaGroundTruth).Count

Write-Host ""
Write-Host "+============================================================+" -ForegroundColor Green
Write-Host "|   DATASET DE AMENAZAS v5.0 - GENERADO                     |" -ForegroundColor Green
Write-Host "+============================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "logs_amenazas.csv          -> $totalAmenazas registros"           -ForegroundColor Yellow
Write-Host "ground_truth_eventos.csv   -> $totalGT eventos maliciosos reales" -ForegroundColor Yellow
Write-Host ""
Write-Host "Esquema ground_truth_eventos.csv (8 col):" -ForegroundColor Gray
Write-Host "  CustomTimestamp, UserPrincipalName, ThreatType, ThreatInstance," -ForegroundColor Gray
Write-Host "  Department, Country, Operation, Result"                          -ForegroundColor Gray
Write-Host ""
Write-Host "DIFERENCIA v5.0 vs v4.0:" -ForegroundColor Cyan
Write-Host "  v4.0 -> 50 filas (1 por usuario comprometido)"                   -ForegroundColor White
Write-Host "  v5.0 -> ~7.000-9.000 filas (1 por EVENTO malicioso real)"        -ForegroundColor White
Write-Host ""
Write-Host "Que entra en ground truth por amenaza:" -ForegroundColor Cyan
Write-Host "  BruteForce APT        -> todos los intentos desde IPs atacantes" -ForegroundColor White
Write-Host "  Exfiltracion Insider  -> reconocimiento nocturno + exfiltracion + lateral" -ForegroundColor White
Write-Host "  GeoAnomaly VPN        -> todos los accesos desde IPs rotando"    -ForegroundColor White
Write-Host "  Phishing Takeover     -> solo los accesos del ATACANTE (no del usuario real)" -ForegroundColor White
Write-Host "  Ransomware            -> beacons C2 + cifrado masivo + borrado backups" -ForegroundColor White
Write-Host ""
Write-Host "(!)  ground_truth_eventos.csv es SOLO para evaluar. NUNCA para entrenar." -ForegroundColor DarkRed