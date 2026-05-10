Detección Inteligente de Anomalías y Amenazas de Seguridad en Entornos Cloud
Trabajo Fin de Grado — Grado en Datos y Analítica de Negocio
ESIC Business & Marketing School | Curso académico 2025/2026
Autores: Pablo García Suárez · Víctor Casas Mateos
Tutor: Jesús García García-Doncel
Tipo de proyecto: Definición e implantación de un proyecto de Big Data
Sector: Tecnología y Telecomunicaciones

Descripción
Este proyecto diseña e implementa un sistema de detección de anomalías no supervisado sobre logs sintéticos de Azure Storage, simulando el entorno de seguridad de una empresa multinacional. El objetivo es demostrar que el machine learning no supervisado, combinado con un feature engineering orientado a IOCs reales, es una alternativa eficaz a los sistemas de detección basados en reglas estáticas.
Se generó un dataset sintético de ~430.000 registros que combina actividad normal de 300 usuarios con 5 tipos de ataques reales (~5% de contaminación). Sobre este dataset se entrenaron y compararon 13 modelos de detección de anomalías de distintas familias, evaluados con un ground truth separado que nunca fue expuesto al entrenamiento.

Arquitectura del entorno simulado
El entorno replica una empresa multinacional con:
  •	300 usuarios distribuidos en 7 sedes internacionales: Madrid, Berlín, Londres, Milán, Varsovia, Nueva York y Los Ángeles
  •	6 contenedores Azure Storage con distintos niveles de criticidad: 
    o	finanzas/, it-sistemas/, directivos/ → Alta criticidad	
    o	recursos-humanos/ → Media criticidad
    o	marketing/, shared/ → Baja criticidad
Control de acceso RBAC por departamento: 
  o	IT y Dirección → Owner (permisos totales)
  o	Finanzas → Contributor (lectura + escritura)
  o	Resto de departamentos → Reader
  
Amenazas simuladas
Los cinco ataques están diseñados bajo IOCs alineados con el framework MITRE ATT&CK:
Amenaza	                  IOCs principales

BruteForce APT	          IsFailedOrDenied alto + IsExternalNetwork + escalada progresiva de volumen
Exfiltración Insider	    Actividad en horas 1-5am + IsUnknownDevice + DailyOpsVolume extremo
GeoAnomaly VPN	          UniqueCountriesPerDay alto + rotación sistemática de países
Phishing Takeover	        Dos países distintos en el mismo UPN el mismo día + dispositivo desconocido
Ransomware	              UniqueContainersPerDay=6 + IsWriteOrDelete masivo + beacons C2 externos
