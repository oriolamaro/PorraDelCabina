import os
import logging
from datetime import date
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from supabase import create_client

log = logging.getLogger(__name__)

# Carreguem les variables ocultes de l'arxiu .env
load_dotenv() 

URL = os.getenv("SUPABASE_URL")
KEY = os.getenv("SUPABASE_SERVICE_KEY")

if not URL or not KEY:
    raise EnvironmentError(
        "❌ Falten SUPABASE_URL o SUPABASE_SERVICE_KEY al fitxer .env"
    )

supabase = create_client(URL, KEY)


# ==========================================
# GESTIÓ DE RESERVES
# ==========================================

def pujar_reserva(negoci_uuid: str, dades_extretes: Dict[str, Any], telefon_client: str = "") -> Optional[List[Dict]]:
    """
    Puja les dades de la reserva a la taula 'reserves'.
    'dades_extretes' ha de ser un diccionari (JSON).
    Si es passa 'telefon_client', es guarda dins les dades per poder identificar-la després.
    """
    if not dades_extretes:
        log.warning("[DB] Intent de pujar reserva amb dades buides. Ignorat.")
        return None
    
    # Línia de seguretat: per evitar errors de claus inexistents segons el negoci
    if "taules_assignades" not in dades_extretes and "servei" not in dades_extretes:
        dades_extretes["info_extra"] = "Reserva genèrica"

    # Guardar el telèfon del client si es proporciona
    if telefon_client:
        dades_extretes["_telefon_client"] = telefon_client

    objecte_reserva = {
        "negoci_id": negoci_uuid,
        "dades_reserva": dades_extretes
    }
    
    try:
        res = supabase.table("reserves").insert(objecte_reserva).execute()
        return res.data
    except Exception as e:
        log.error("[DB] Error pujant reserva: %s", e)
        return None


def obtenir_reserves(negoci_uuid: str) -> List[Dict[str, Any]]:
    """Obté totes les reserves d'un negoci (per tot l'historial, eviteu usar en producció diària)."""
    try:
        res = supabase.table("reserves").select("*").eq("negoci_id", negoci_uuid).execute()
        
        reserves_netes = []
        for fila in res.data:
            dades = fila.get("dades_reserva", {})
            if dades:
                reserves_netes.append(dades)
            
        return reserves_netes
    except Exception as e:
        log.error("[DB] Error obtenint reserves: %s", e)
        return []


def obtenir_reserves_per_data(negoci_uuid: str, data_str: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Obté les reserves d'un negoci filtrades per data.
    Si no es passa data, retorna les d'avui.
    
    La data ha d'estar en format ISO: "2026-03-20"
    """
    if not data_str:
        data_str = date.today().isoformat()
    
    try:
        # Aprofitem la capacitat nativa de Supabase (Postgres) per filtrar dins de JSONB
        res = supabase.table("reserves") \
            .select("dades_reserva") \
            .eq("negoci_id", negoci_uuid) \
            .eq("dades_reserva->>data", data_str) \
            .execute()
        
        reserves = []
        for fila in res.data:
            dades = fila.get("dades_reserva", {})
            if dades:
                reserves.append(dades)
                
        return reserves
    except Exception as e:
        log.error("[DB] Error obtenint reserves per data %s: %s", data_str, e)
        return []


def obtenir_reserves_per_telefon(negoci_uuid: str, telefon: str) -> List[Dict[str, Any]]:
    """Obté les reserves futures d'un negoci associades a un número de telèfon."""
    if not telefon or telefon == "Desconegut":
        return []
    try:
        res = supabase.table("reserves") \
            .select("id, dades_reserva") \
            .eq("negoci_id", negoci_uuid) \
            .eq("dades_reserva->>_telefon_client", telefon) \
            .execute()
        
        reserves = []
        avui = date.today().isoformat()
        for fila in res.data:
            dades = fila.get("dades_reserva", {})
            if dades and dades.get("data", "") >= avui:
                dades["_id_reserva"] = fila.get("id")
                reserves.append(dades)
                
        return reserves
    except Exception as e:
        log.error("[DB] Error obtenint reserves per telèfon %s: %s", telefon, e)
        return []


def eliminar_reserva(reserva_id: str, negoci_uuid: str) -> bool:
    """Elimina una reserva concreta pel seu ID de la BD."""
    try:
        res = supabase.table("reserves") \
            .delete() \
            .eq("id", reserva_id) \
            .eq("negoci_id", negoci_uuid) \
            .execute()
        return len(res.data) > 0
    except Exception as e:
        log.error("[DB] Error eliminant reserva %s: %s", reserva_id, e)
        return False


# ==========================================
# CONFIGURACIÓ UNIVERSAL DEL NEGOCI
# ==========================================

def obtenir_dades_negoci(agent_id_slug: str) -> Optional[Dict[str, Any]]:
    """
    Recupera TOTA la configuració d'un negoci des de Supabase usant el seu slug.
    Això alimenta el cervell de l'agent i els algorismes de disponibilitat.
    """
    try:
        res = supabase.table("negocis") \
            .select("id, nom_negoci, tipus_negoci, system_prompt, camps_requerits, configuracio_extra, missatge_inicial") \
            .eq("agent_id", agent_id_slug) \
            .single() \
            .execute()
        
        if res.data:
            return {
                "uuid": res.data.get('id'),
                "nom": res.data.get('nom_negoci', 'Negoci sense nom'),
                "tipus": res.data.get('tipus_negoci', 'restaurant'),
                "prompt_base": res.data.get('system_prompt', ''),
                "camps_requerits": res.data.get('camps_requerits') or ["hora", "data", "persones", "nom"],
                "configuracio_extra": res.data.get('configuracio_extra') or {},
                "missatge_inicial": res.data.get('missatge_inicial')
            }
        
        return None
    except Exception as e:
        log.error("[DB] Error obtenint dades del negoci '%s': %s", agent_id_slug, e)
        return None