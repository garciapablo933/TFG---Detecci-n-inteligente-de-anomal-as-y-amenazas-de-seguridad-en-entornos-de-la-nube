import pandas as pd
import os

# =============================================================
# PIPELINE DE UNIÓN — Dataset Final TFG
# =============================================================
# Mezcla TODOS los logs sin etiquetas de ningún tipo.
# El modelo no sabe cuál es bueno o malo — aprende solo
# de los patrones, exactamente como en un entorno real.
#
# ground_truth_eventos.csv se usa SOLO para evaluar después,
# nunca para entrenar.
# =============================================================

PATH_NORMAL       = "../Data/logs_normales.csv"
PATH_AMENAZAS     = "../Data/logs_amenazas.csv"
PATH_GROUND_TRUTH = "../Data/ground_truth_eventos.csv"
PATH_SALIDA       = "../Data/dataset_final_TFG.csv"

COLUMNAS_ESPERADAS = [
    "CustomTimestamp", "UserPrincipalName", "Department", "Office",
    "Country", "Operation", "Resource", "Result", "IP_Address",
    "NetworkType", "Device_ID", "Resource_Criticality", "UserProfile"
]

def validar_esquema(df, nombre):
    faltantes = [c for c in COLUMNAS_ESPERADAS if c not in df.columns]
    if faltantes:
        print(f"  ❌ {nombre} — columnas faltantes: {faltantes}")
        return False
    print(f"  ✅ {nombre} — esquema correcto ({len(df):,} registros)")
    return True

def pipeline():
    print("=" * 55)
    print("  PIPELINE DE UNIÓN — Dataset TFG Anomalías Azure")
    print("=" * 55)

    # ── FASE 1: Carga ─────────────────────────────────────────
    print("\n[1/4] Cargando archivos...")
    for path in [PATH_NORMAL, PATH_AMENAZAS]:
        if not os.path.exists(path):
            print(f"  ❌ No se encuentra: {path}")
            print("     Ejecuta primero los scripts PowerShell.")
            return

    df_normal   = pd.read_csv(PATH_NORMAL,   encoding="utf-8-sig")
    df_amenazas = pd.read_csv(PATH_AMENAZAS, encoding="utf-8-sig")

    print(f"  logs_normales.csv  → {len(df_normal):,} registros")
    print(f"  logs_amenazas.csv  → {len(df_amenazas):,} registros")

    # ── FASE 2: Validación de esquema ─────────────────────────
    print("\n[2/4] Validando esquema maestro (13 columnas)...")
    if not (validar_esquema(df_normal,   "logs_normales.csv") and
            validar_esquema(df_amenazas, "logs_amenazas.csv")):
        print("\n  ⚠️  Esquemas incompatibles — revisa los scripts PowerShell.")
        return

    # ── FASE 3: Unión cronológica SIN etiquetas ───────────────
    # Se mezclan TODOS los registros tal cual.
    # Ninguna columna indica si el log es bueno o malo.
    print("\n[3/4] Mezclando y ordenando cronológicamente...")

    df = pd.concat([df_normal, df_amenazas], ignore_index=True)
    df["CustomTimestamp"] = pd.to_datetime(df["CustomTimestamp"])
    df = df.sort_values("CustomTimestamp").reset_index(drop=True)

    print(f"  → Total registros:  {len(df):,}")
    print(f"  → Rango temporal:   {df['CustomTimestamp'].min()} → {df['CustomTimestamp'].max()}")
    print(f"  → Usuarios únicos:  {df['UserPrincipalName'].nunique()}")

    # Info orientativa de contaminación real (solo para referencia, no entra en el modelo)
    if os.path.exists(PATH_GROUND_TRUTH):
        df_gt = pd.read_csv(PATH_GROUND_TRUTH, encoding="utf-8-sig")
        n_mal = len(df_gt)
        pct   = n_mal / len(df) * 100
        print(f"\n  ℹ️  Referencia de contaminación real (ground truth):")
        print(f"     {n_mal:,} eventos maliciosos = {pct:.1f}% del dataset total")
        print(f"     (esta info NO entra en el modelo)")

    # ── FASE 4: Feature Engineering para ML ───────────────────
    print("\n[4/4] Feature Engineering para ML...")

    df["Hour"]              = df["CustomTimestamp"].dt.hour
    df["DayOfWeek"]         = df["CustomTimestamp"].dt.dayofweek
    df["IsOfficeHours"]     = df["Hour"].between(8, 18).astype(int)
    df["IsWeekend"]         = (df["DayOfWeek"] >= 5).astype(int)
    df["IsUnknownDevice"]   = df["Device_ID"].str.startswith("UNKNOWN-BYOD").astype(int)
    df["IsExternalNetwork"] = (df["NetworkType"] == "External").astype(int)
    df["IsHighCriticality"] = (df["Resource_Criticality"] == "High").astype(int)
    df["IsFailedOrDenied"]  = df["Result"].isin(["Failed", "Denied"]).astype(int)
    df["IsWriteOrDelete"]   = df["Operation"].isin(["StorageWrite", "StorageDelete"]).astype(int)

    df["_date"] = df["CustomTimestamp"].dt.date

    # Volumen diario por usuario (IOC ransomware / exfiltración masiva)
    vol = df.groupby(["UserPrincipalName", "_date"]).size().reset_index(name="DailyOpsVolume")
    df  = df.merge(vol, on=["UserPrincipalName", "_date"], how="left")

    # Países únicos por usuario por día (IOC phishing)
    paises = df.groupby(["UserPrincipalName", "_date"])["Country"].nunique().reset_index(name="UniqueCountriesPerDay")
    df     = df.merge(paises, on=["UserPrincipalName", "_date"], how="left")

    # Contenedores únicos por usuario por día (IOC ransomware)
    df["_container"] = df["Resource"].str.extract(r'^(/[^/]+/)')
    conts = df.groupby(["UserPrincipalName", "_date"])["_container"].nunique().reset_index(name="UniqueContainersPerDay")
    df    = df.merge(conts, on=["UserPrincipalName", "_date"], how="left")

    df.drop(columns=["_date", "_container"], inplace=True)

    print(f"  → 12 features añadidas: Hour, DayOfWeek, IsOfficeHours, IsWeekend,")
    print(f"    IsUnknownDevice, IsExternalNetwork, IsHighCriticality,")
    print(f"    IsFailedOrDenied, IsWriteOrDelete, DailyOpsVolume,")
    print(f"    UniqueCountriesPerDay, UniqueContainersPerDay")
    print(f"  → Total columnas: {len(df.columns)}  (13 base + 12 features ML)")

    # ── Guardado ───────────────────────────────────────────────
    os.makedirs(os.path.dirname(PATH_SALIDA), exist_ok=True)
    df.to_csv(PATH_SALIDA, index=False, encoding="utf-8")

    # ── Resumen final ──────────────────────────────────────────
    print("\n" + "=" * 55)
    print("  PIPELINE COMPLETADO")
    print("=" * 55)
    print(f"  📁 {PATH_SALIDA}")
    print(f"  📊 {len(df):,} registros × {len(df.columns)} columnas")
    print(f"  👤 {df['UserPrincipalName'].nunique()} usuarios únicos")
    print()
    print(f"  Distribución de operaciones:")
    for op, cnt in df["Operation"].value_counts().items():
        print(f"    {op:<20} {cnt:>8,}")
    print(f"\n  Distribución NetworkType:")
    for nt, cnt in df["NetworkType"].value_counts().items():
        print(f"    {nt:<20} {cnt:>8,}")
    print()
    print(f"  ⚠️  Dataset SIN etiquetas.")
    print(f"     Usa ground_truth_eventos.csv SOLO para evaluar")
    print(f"     precision/recall después de entrenar el modelo.")

if __name__ == "__main__":
    pipeline()