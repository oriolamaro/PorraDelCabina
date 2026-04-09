import json
import logging
import re
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from base_dades import (
    pujar_reserva,
    obtenir_reserves_per_data,
    obtenir_dades_negoci,
    obtenir_reserves_per_telefon,
    eliminar_reserva,
)
from motor_reserves import processar_reserva

log = logging.getLogger(__name__)

# =====================================
# EINES DE VALIDACIÓ
# =====================================

def _sanititzar_text(text: str, max_len: int = 200) -> str:
    """Retalla, neteja espais i limita la longitud d'un text."""
    if not isinstance(text, str):
        text = str(text)
    text = text.strip()
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text[:max_len]


def _validar_hora(hora: Any) -> Optional[str]:
    """Retorna l'hora en format HH:MM si és vàlida, o None."""
    if not isinstance(hora, str):
        return None
    hora = hora.strip()
    hora = hora.replace(".", ":")
    if not re.match(r"^\d{1,2}:\d{2}$", hora):
        return None
    try:
        dt = datetime.strptime(hora, "%H:%M")
        return dt.strftime("%H:%M")
    except ValueError:
        return None


def _validar_data(data: Any) -> Optional[str]:
    """Retorna la data en format ISO YYYY-MM-DD si és vàlida i no és en el passat."""
    if not isinstance(data, str):
        return None
    data = data.strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", data):
        return None
    try:
        dt = datetime.strptime(data, "%Y-%m-%d").date()
        if dt < date.today():
            log.warning("[VALIDACIÓ] Data en el passat rebutjada: %s", data)
            return None
        return dt.isoformat()
    except ValueError:
        return None


def _validar_persones(val: Any) -> Optional[int]:
    """Retorna un enter positiu, o None si el valor no és vàlid."""
    try:
        n = int(val)
        if 1 <= n <= 500:
            return n
        return None
    except (TypeError, ValueError):
        return None


def _validar_hora_dins_horari(hora_str: str, config_extra: Dict[str, Any], data_str: Optional[str] = None) -> Optional[str]:
    """
    Comprova que l'hora cau dins dels horaris permesos del negoci.
    - Si 'horaris' és un diccionari (nou format), comprova el dia corresponent.
    - Si 'horaris' és una llista (format antic), comprova si l'hora és a la llista.
    - Si no hi ha horaris definits, accepta qualsevol hora.
    """
    horaris = config_extra.get("horaris")
    if not horaris:
        return None

    tipus_negoci = str(config_extra.get("tipus_negoci", "")).lower()
    if tipus_negoci == "hotel":
        return None  # Hotels normalment no bloquegen reserves per "hora numèrica" exacta, l'horari és orientatiu

    # NOVES LÒGIQUES DE DICCIONARI (DASHBOARD)
    if isinstance(horaris, dict) and data_str:
        try:
            dt = datetime.strptime(data_str, "%Y-%m-%d")
            # weekday() torna 0=dilluns, ..., 6=diumenge
            dias_map = {0: 'monday', 1: 'tuesday', 2: 'wednesday', 3: 'thursday', 4: 'friday', 5: 'saturday', 6: 'sunday'}
            clau_dia = dias_map.get(dt.weekday())
            
            day_data = horaris.get(clau_dia)
            if not day_data:
                return None # No hi ha info d'aquest dia
            
            if day_data.get("closed"):
                return "El negoci està tancat aquest dia."
            
            h_open = day_data.get("open", day_data.get("obertura", "00:00"))
            
            # Use specific limit for reservations if configured, otherwise fallback to the old "close" or generic "23:59"
            h_close = day_data.get("close_reserves", day_data.get("close", day_data.get("tancament", "23:59")))
            
            # Comparació d'strings (HH:MM) funciona bé
            if not (h_open <= hora_str <= h_close):
                return f"L'hora {hora_str} està fora de l'horari permès per a acceptar noves reserves ({h_open} - {h_close} límit)."
                
            return None
        except (ValueError, KeyError):
            return None

    # LÒGICA ANTIGA (LLISTA) PER COMPATIBILITAT
    if isinstance(horaris, list) and len(horaris) > 0:
        horaris_normalitzats = []
        for h in horaris:
            h_val = _validar_hora(h)
            if h_val:
                horaris_normalitzats.append(h_val)

        if not horaris_normalitzats:
            return None

        if hora_str not in horaris_normalitzats:
            return f"L'hora {hora_str} no està dins dels horaris permesos: {', '.join(sorted(horaris_normalitzats))}."
            
    return None


def _validar_dia_obert(data_str: str, config_extra: Dict[str, Any]) -> Optional[str]:
    """
    Comprova que el dia de la setmana no és un dia tancat.
    - Mira si hi ha un diccionari 'horaris' amb la clau 'closed'.
    - Mira si hi ha una llista 'dies_tancats' (format antic).
    """
    try:
        dt = datetime.strptime(data_str, "%Y-%m-%d")
    except ValueError:
        return None

    dies_festius = config_extra.get("dies_festius")
    if dies_festius and isinstance(dies_festius, list):
        if data_str in dies_festius:
            return "El negoci està ple o tancat completament en aquesta data (calendari de dies bloquejats)."

    horaris = config_extra.get("horaris")
    if isinstance(horaris, dict):
        dias_map = {0: 'monday', 1: 'tuesday', 2: 'wednesday', 3: 'thursday', 4: 'friday', 5: 'saturday', 6: 'sunday'}
        clau_dia = dias_map.get(dt.weekday())
        day_data = horaris.get(clau_dia)
        if day_data and day_data.get("closed"):
            return "El negoci està tancat per descans setmanal aquest dia."

    dies_tancats = config_extra.get("dies_tancats")
    if dies_tancats and isinstance(dies_tancats, list):
        # Mapatge de dia de la setmana en múltiples idiomes
        noms_dia = {
            0: ["dilluns", "lunes", "monday"],
            1: ["dimarts", "martes", "tuesday"],
            2: ["dimecres", "miércoles", "miercoles", "wednesday"],
            3: ["dijous", "jueves", "thursday"],
            4: ["divendres", "viernes", "friday"],
            5: ["dissabte", "sábado", "sabado", "saturday"],
            6: ["diumenge", "domingo", "sunday"],
        }
        dia_setmana = dt.weekday()
        noms_avui = noms_dia.get(dia_setmana, [])

        for dia_tancat in dies_tancats:
            if dia_tancat.lower().strip() in noms_avui:
                return f"El negoci tanca els {dia_tancat}."

    return None


# =====================================
# REGISTRE DE CAMPS CONEGUTS
# =====================================
# Cada camp té: type (JSON Schema), description, i opcionalment una funció
# de validació. Si un camp de `camps_requerits` no és aquí, es tractarà
# com a string genèric amb sanitització automàtica.

CAMP_REGISTRY: Dict[str, Dict[str, Any]] = {
    "nom": {
        "type": "string",
        "description": "Nom i cognom real del client. MAI INVENTIS AQUEST CAMP. Si no us ho ha dit, pregunta-ho explícitament: 'A quin nom faig la reserva?'",
        "max_len": 100,
    },
    "persones": {
        "type": "integer",
        "description": "Nombre de persones (>0).",
    },
    "hora": {
        "type": "string",
        "description": "Hora desitjada en format HH:MM (24h). Exemple: '21:00'.",
    },
    "data": {
        "type": "string",
        "description": "Data en format ISO YYYY-MM-DD. Exemple: '2026-03-25'.",
    },
    "servei": {
        "type": "string",
        "description": "Tipus de servei sol·licitat pel client.",
        "max_len": 100,
    },
    "observacions": {
        "type": "string",
        "description": "Observacions o peticions especials del client (opcional).",
        "max_len": 300,
    },
    "telefon": {
        "type": "string",
        "description": "Número de telèfon del client.",
        "max_len": 20,
    },
    "email": {
        "type": "string",
        "description": "Correu electrònic del client.",
        "max_len": 200,
    },
}


def _extreure_noms_camps(camps_requerits: List[Any]) -> List[str]:
    """
    Extreu només els noms dels camps de la llista, ja sigui una llista de strings
    o una llista de diccionaris [{"camp": "...", "descripcio": "..."}].
    """
    noms = []
    for item in camps_requerits:
        if isinstance(item, dict) and "camp" in item:
            noms.append(item["camp"])
        elif isinstance(item, str):
            noms.append(item)
    return noms


def _validar_args_tool(args: Dict[str, Any], camps_requerits: List[Any]) -> Tuple[bool, str]:
    """
    Valida i neteja els arguments del LLM de forma dinàmica.
    Utilitza CAMP_REGISTRY per als camps coneguts; els desconeguts es sanititzen com a text.
    """
    errors = []
    
    # Comprovar primer que hi siguin tots els camps requerits (excepte si són opcionals per naturalesa com observacions)
    noms_requerits = _extreure_noms_camps(camps_requerits)
    for req in noms_requerits:
        if req not in args and req != "observacions":
            errors.append(f"Falta el camp obligatori '{req}'. Has de preguntar-ho al client abans de continuar.")

    for camp in list(args.keys()):
        # Ignorar camps interns (prefixats amb _)
        if camp.startswith("_"):
            continue

        if camp == "hora":
            hora_v = _validar_hora(args["hora"])
            if hora_v is None:
                errors.append(f"L'hora '{args['hora']}' no té format vàlid (HH:MM).")
            else:
                args["hora"] = hora_v
        elif camp == "data":
            data_v = _validar_data(args["data"])
            if data_v is None:
                errors.append(f"La data '{args['data']}' no és vàlida o és en el passat.")
            else:
                args["data"] = data_v
        elif camp == "persones":
            p_v = _validar_persones(args["persones"])
            if p_v is None:
                errors.append(f"El nombre de persones '{args['persones']}' no és vàlid (1-500).")
            else:
                args["persones"] = p_v
        elif camp in CAMP_REGISTRY:
            # Camp conegut de tipus string → sanititzar i validar fakes
            info = CAMP_REGISTRY[camp]
            if info["type"] == "string":
                max_len = info.get("max_len", 200)
                text_net = _sanititzar_text(args.get(camp, ""), max_len=max_len)
                
                # Regla de robustesa pel nom: el LLM a vegades inventa noms genèrics si se n'oblida
                if camp == "nom" and text_net.lower() in ["client", "desconegut", "anònim", "anonim", "no ho sé", ""]:
                    errors.append("El nom no és vàlid. NO inventis el nom. Has de preguntar-lo explícitament al client.")
                else:
                    args[camp] = text_net
        else:
            # Camp completament desconegut → sanititzar com a text genèric
            if isinstance(args.get(camp), str):
                text_net = _sanititzar_text(args[camp], max_len=200)
                if camp == "nom" and text_net.lower() in ["client", "desconegut", "anònim", "anonim", ""]:
                    errors.append("El nom no és vàlid. NO inventis el nom. Pregunta-ho al client.")
                else:
                    args[camp] = text_net

    if errors:
        return False, " | ".join(errors)
    return True, ""


# =====================================
# GENERACIÓ DINÀMICA DE TOOLS
# =====================================

def _generar_propietats_camps(camps_requerits: List[Any]) -> Dict[str, Any]:
    """
    Genera el bloc 'properties' del JSON Schema a partir de la llista de camps requerits.
    Suporta strings purs o objectes {"camp": "...", "descripcio": "..."}.
    Afegeix sempre 'observacions' com a camp opcional.
    """
    props: Dict[str, Any] = {}
    
    for item in camps_requerits:
        # 1. Extreure nom del camp i descripció custom si n'hi ha
        nom_camp = item["camp"] if isinstance(item, dict) else item
        desc_custom = item.get("descripcio") if isinstance(item, dict) else None
        
        # 2. Assignar propietats
        if nom_camp in CAMP_REGISTRY:
            info = CAMP_REGISTRY[nom_camp]
            props[nom_camp] = {
                "type": info["type"],
                "description": desc_custom if desc_custom else info["description"],
            }
        else:
            # Camp personalitzat genèric
            desc_gen = f"{nom_camp.replace('_', ' ').capitalize()} (camp personalitzat del negoci)."
            props[nom_camp] = {
                "type": "string",
                "description": desc_custom if desc_custom else desc_gen,
            }

    return props


def generar_tools(camps_requerits: List[Any]) -> List[Dict[str, Any]]:
    """
    Genera la llista de TOOLS dinàmicament segons els camps requerits.
    """
    propietats = _generar_propietats_camps(camps_requerits)
    # Llista només amb els noms dels camps per al 'required'
    noms_camps = _extreure_noms_camps(camps_requerits)

    return [
        {
            "type": "function",
            "function": {
                "name": "comprovar_disponibilitat",
                "description": (
                    "Comprova si hi ha disponibilitat per a una reserva. "
                    "Crida aquesta funció ABANS de confirmar. "
                    "Retorna si hi ha lloc o no, i el motiu si no n'hi ha."
                ),
                "parameters": {
                    "type": "object",
                    "properties": propietats,
                    "required": noms_camps,
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "confirmar_reserva",
                "description": (
                    "Confirma i insereix la reserva a la base de dades. "
                    "Crida NOMÉS si l'usuari ha confirmat explícitament "
                    "I comprovar_disponibilitat ha retornat disponible=true."
                ),
                "parameters": {
                    "type": "object",
                    "properties": propietats,
                    "required": noms_camps,
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "cancellar_reserva",
                "description": (
                    "Cancel·la una reserva existent. "
                    "Només si l'usuari indica explícitament que vol cancel·lar. "
                    "La cerca es fa automàticament pel número de telèfon. "
                    "Si té varies reserves, cal que especifiqui data i/o hora."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "data": {
                            "type": "string",
                            "description": "Data de la reserva a cancel·lar en format ISO YYYY-MM-DD (si l'ha especificat).",
                        },
                        "hora": {
                            "type": "string",
                            "description": "Hora de la reserva a cancel·lar en format HH:MM (si l'ha especificat).",
                        },
                    },
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "modificar_reserva",
                "description": (
                    "Modifica una reserva existent canviant-ne la data, hora o nombre de persones. "
                    "La cerca de la reserva original es fa automàticament pel telèfon. "
                    "Si no hi ha lloc per la nova configuració, es manté l'original intacta."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "data_original": {
                            "type": "string",
                            "description": "Data original en format ISO YYYY-MM-DD (per identificar-la si en té varies).",
                        },
                        "hora_original": {
                            "type": "string",
                            "description": "Hora original en format HH:MM (per identificar-la si en té varies).",
                        },
                        "persones_noves": {
                            "type": "integer",
                            "description": "Nou nombre de persones (>0).",
                        },
                        "hora_nova": {
                            "type": "string",
                            "description": "Nova hora desitjada en format HH:MM (24h).",
                        },
                        "data_nova": {
                            "type": "string",
                            "description": "Nova data en format ISO YYYY-MM-DD.",
                        },
                    },
                    "required": ["hora_nova", "data_nova", "persones_noves"],
                    "additionalProperties": False,
                },
            },
        },
    ]


# =====================================
# IMPLEMENTACIÓ DE LES TOOLS
# =====================================

def _executar_comprovar_disponibilitat(args: Dict[str, Any], config_negoci: Dict[str, Any]) -> str:
    """Executa la verificació real de disponibilitat i retorna un JSON amb el resultat."""
    uuid_negoci  = config_negoci.get("uuid")
    tipus_negoci = config_negoci.get("tipus", "restaurant")
    config_extra = config_negoci.get("configuracio_extra", {})
    data_str     = args.get("data", date.today().isoformat())
    hora_str     = args.get("hora", "00:00")

    log.info("[TOOL] comprovar_disponibilitat: %s persones a les %s del %s",
             args.get("persones"), hora_str, data_str)

    # Validació programàtica d'horaris i dies tancats
    error_horari = _validar_hora_dins_horari(hora_str, config_extra, data_str)
    if error_horari:
        log.warning("[VALIDACIÓ] %s", error_horari)
        return json.dumps({"disponible": False, "motiu": error_horari}, ensure_ascii=False)

    error_dia = _validar_dia_obert(data_str, config_extra)
    if error_dia:
        log.warning("[VALIDACIÓ] %s", error_dia)
        return json.dumps({"disponible": False, "motiu": error_dia}, ensure_ascii=False)

    try:
        reserves_fetes = obtenir_reserves_per_data(uuid_negoci, data_str)
        acceptades, rebutjades = processar_reserva(
            tipus_negoci, args, reserves_fetes, config_extra
        )
    except Exception as e:
        log.error("[TOOL ERROR] comprovar_disponibilitat: %s", e)
        return json.dumps({"disponible": False, "motiu": f"Error intern comprovant disponibilitat: {e}"}, ensure_ascii=False)

    if acceptades:
        return json.dumps({"disponible": True, "motiu": "Hi ha disponibilitat."}, ensure_ascii=False)
    else:
        motiu = rebutjades[0].get("motiu", "No hi ha disponibilitat.") if rebutjades else "No hi ha disponibilitat."
        return json.dumps({"disponible": False, "motiu": motiu}, ensure_ascii=False)


def _executar_confirmar_reserva(args: Dict[str, Any], config_negoci: Dict[str, Any]) -> str:
    """Executa la reserva definitiva i la guarda a la BD. Retorna un JSON amb el resultat."""
    uuid_negoci  = config_negoci.get("uuid")
    tipus_negoci = config_negoci.get("tipus", "restaurant")
    config_extra = config_negoci.get("configuracio_extra", {})
    data_str     = args.get("data", date.today().isoformat())
    nom          = args.get("nom", "Client")
    persones     = args.get("persones")
    hora         = args.get("hora")
    telefon      = args.get("_telefon_client", "")

    log.info("[TOOL] confirmar_reserva: %s | %s pax | %s | %s", nom, persones, hora, data_str)

    try:
        # Doble comprovació en temps real (evitar concurrència)
        reserves_fetes = obtenir_reserves_per_data(uuid_negoci, data_str)
        acceptades, rebutjades = processar_reserva(
            tipus_negoci, args, reserves_fetes, config_extra
        )
    except Exception as e:
        log.error("[TOOL ERROR] confirmar_reserva (comprovació): %s", e)
        return json.dumps({"exit": False, "missatge": f"Error intern verificant disponibilitat: {e}"}, ensure_ascii=False)

    if not acceptades:
        motiu = rebutjades[0].get("motiu", "No hi ha disponibilitat.") if rebutjades else "No hi ha disponibilitat."
        log.warning("[CONCURRÈNCIA] Reserva rebutjada a l'últim moment: %s", motiu)
        return json.dumps({"exit": False, "missatge": motiu}, ensure_ascii=False)

    reserva_definitiva = acceptades[0]

    try:
        resultat_db = pujar_reserva(uuid_negoci, reserva_definitiva, telefon_client=telefon)
        if resultat_db is None:
            return json.dumps({"exit": False, "missatge": "Error guardant la reserva a la base de dades. Torna-ho a intentar."}, ensure_ascii=False)
    except Exception as e:
        log.error("[TOOL ERROR] confirmar_reserva (inserció): %s", e)
        return json.dumps({"exit": False, "missatge": f"Error guardant la reserva: {e}"}, ensure_ascii=False)

    # Construir missatge de confirmació segons el tipus
    if tipus_negoci == "restaurant":
        taules_str = ", ".join(reserva_definitiva.get("taules_assignades", []))
        log.info("[DB] 💾 INSERIT: %s | %s pax | %s | %s | Taules: %s", nom, persones, hora, data_str, taules_str)
        return json.dumps({
            "exit": True,
            "missatge": f"Reserva confirmada per a {persones} persones a les {hora} del {data_str}. Taules assignades: {taules_str}."
        }, ensure_ascii=False)
    else:
        servei = reserva_definitiva.get("servei", "servei")
        log.info("[DB] 💾 INSERIT: %s | %s | %s | %s", nom, servei, hora, data_str)
        return json.dumps({
            "exit": True,
            "missatge": f"Reserva de {servei} confirmada a les {hora} del {data_str} a nom de {nom}."
        }, ensure_ascii=False)


# =====================================
# CANCEL·LACIÓ I MODIFICACIÓ
# =====================================

def _buscar_reserva_per_telefon(
    telefon: str,
    uuid_negoci: str,
    data: Optional[str] = None,
    hora: Optional[str] = None
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Busca una reserva a la BD pel número de telèfon.
    Si hi ha múltiples reserves, filtra per data/hora.
    Retorna (trobada, missatge, dades_reserva).
    """
    if not telefon or telefon == "Desconegut":
        return False, "Només pots gestionar reserves si truques des del mateix número amb el qual vas fer la reserva.", None

    reserves_usuari = obtenir_reserves_per_telefon(uuid_negoci, telefon)
    if not reserves_usuari:
        return False, "No s'ha trobat cap reserva activa associada a aquest número de telèfon.", None

    # Filtrar per data i hora si s'han proporcionat
    matches = reserves_usuari
    if data:
        matches = [r for r in matches if r.get("data") == data]
    if hora:
        matches = [r for r in matches if r.get("hora") == hora]

    if len(matches) == 0:
        info = [f"{r.get('data')} a les {r.get('hora')}" for r in reserves_usuari]
        return False, f"No coincideix amb cap reserva teva. Les teves reserves actives son: {', '.join(info)}.", None
    elif len(matches) > 1:
        info = [f"{r.get('data')} a les {r.get('hora')}" for r in matches]
        return False, f"Tens diverses reserves que coincideixen: {', '.join(info)}. Especifica la data i l'hora exactes.", None

    return True, "Reserva trobada.", matches[0]


def _executar_cancellar_reserva(args: Dict[str, Any], config_negoci: Dict[str, Any]) -> str:
    """Cancel·la la reserva associada al telèfon del client."""
    uuid_negoci = config_negoci.get("uuid", "")
    telefon = args.get("_telefon_client", "Desconegut")
    data_str = args.get("data")
    hora_str = args.get("hora")

    log.info("[TOOL] cancellar_reserva | tel: %s | data: %s | hora: %s", telefon, data_str, hora_str)

    trobada, msg, reserva = _buscar_reserva_per_telefon(telefon, uuid_negoci, data_str, hora_str)
    if not trobada or reserva is None:
        return json.dumps({"exit": False, "missatge": msg}, ensure_ascii=False)

    id_reserva = reserva.get("_id_reserva", "")
    if eliminar_reserva(id_reserva, uuid_negoci):
        nom = reserva.get("nom", "Client")
        data_r = reserva.get("data", "?")
        hora_r = reserva.get("hora", "?")
        log.info("[DB] 🗑️ ELIMINADA: %s | %s | %s", nom, data_r, hora_r)
        return json.dumps({
            "exit": True,
            "missatge": f"La reserva de {nom} del {data_r} a les {hora_r} ha estat cancel·lada correctament."
        }, ensure_ascii=False)
    else:
        return json.dumps({"exit": False, "missatge": "Error intern a la base de dades al cancel·lar."}, ensure_ascii=False)


def _executar_modificar_reserva(args: Dict[str, Any], config_negoci: Dict[str, Any]) -> str:
    """Modifica una reserva existent: esborra la vella i en crea una de nova si hi ha lloc."""
    uuid_negoci = config_negoci.get("uuid", "")
    telefon = args.get("_telefon_client", "Desconegut")
    data_original = args.get("data_original")
    hora_original = args.get("hora_original")

    pax_nou = args.get("persones_noves")
    hora_nova = args.get("hora_nova")
    data_nova = args.get("data_nova")

    log.info("[TOOL] modificar_reserva | tel: %s → %s pax, %s %s", telefon, pax_nou, data_nova, hora_nova)

    # 1. Trobar la reserva original
    trobada, msg, info_vella = _buscar_reserva_per_telefon(telefon, uuid_negoci, data_original, hora_original)
    if not trobada or info_vella is None:
        return json.dumps({"exit": False, "missatge": msg}, ensure_ascii=False)

    # 2. Preparar args per a la nova reserva
    args_nova: Dict[str, Any] = {
        "nom": info_vella.get("nom", "Client"),
        "persones": pax_nou,
        "hora": hora_nova,
        "data": data_nova,
        "_telefon_client": telefon,
    }
    if "servei" in info_vella:
        args_nova["servei"] = info_vella["servei"]
    if "observacions" in info_vella:
        args_nova["observacions"] = info_vella["observacions"]

    # 3. Comprovar disponibilitat per la nova ABANS d'esborrar
    disp_json = _executar_comprovar_disponibilitat(args_nova, config_negoci)
    disp = json.loads(disp_json)

    if not disp.get("disponible"):
        motiu = disp.get("motiu", "Sense capacitat")
        return json.dumps({
            "exit": False,
            "missatge": f"No es pot modificar: {motiu}. La teva reserva original es manté intacta."
        }, ensure_ascii=False)

    # 4. Ara sí: esborrar la vella
    id_vella = info_vella.get("_id_reserva", "")
    if not eliminar_reserva(id_vella, uuid_negoci):
        return json.dumps({"exit": False, "missatge": "Error intern esborrant la reserva original."}, ensure_ascii=False)

    # 5. Confirmar la nova
    result_json = _executar_confirmar_reserva(args_nova, config_negoci)
    result = json.loads(result_json)

    if result.get("exit"):
        log.info("[DB] ✏️ MODIFICADA: %s → %s %s %s pax", telefon, data_nova, hora_nova, pax_nou)
        return json.dumps({
            "exit": True,
            "missatge": f"Reserva modificada correctament. {result.get('missatge', '')}"
        }, ensure_ascii=False)
    else:
        # ROLLBACK: repujar la vella si la nova falla
        log.warning("[TOOL] Rollback: repujant reserva original de %s", telefon)
        info_vella.pop("_id_reserva", None)
        pujar_reserva(uuid_negoci, info_vella, telefon_client=telefon)
        return json.dumps({
            "exit": False,
            "missatge": f"Error creant la nova reserva. He restaurat la teva reserva original."
        }, ensure_ascii=False)


# =====================================
# DISPATCHER CENTRAL DE TOOLS
# =====================================

def executar_tool(tool_name: str, args_raw: str, config_negoci: Dict[str, Any], camps_requerits: List[Any]) -> str:
    """
    Punt d'entrada centralitzat per executar qualsevol tool.
    Valida els arguments, executa la tool i retorna el resultat com a string JSON.
    """
    # 1. Parsejar arguments
    try:
        args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
        if not isinstance(args, dict):
            raise ValueError("Els arguments no són un diccionari.")
    except (json.JSONDecodeError, ValueError) as e:
        log.error("[TOOL] Error parsejant arguments de '%s': %s | Raw: %s", tool_name, e, str(args_raw)[:200])
        return json.dumps({"error": f"Arguments invàlids: {e}"}, ensure_ascii=False)

    # 2. Validar arguments (només per a tools que tenen camps estructurats)
    if tool_name in ("comprovar_disponibilitat", "confirmar_reserva"):
        valid, error_msg = _validar_args_tool(args, camps_requerits)
        if not valid:
            log.warning("[TOOL] Arguments de '%s' no vàlids: %s", tool_name, error_msg)
            return json.dumps({"error": error_msg}, ensure_ascii=False)

    # 3. Executar la tool correcta
    if tool_name == "comprovar_disponibilitat":
        return _executar_comprovar_disponibilitat(args, config_negoci)
    elif tool_name == "confirmar_reserva":
        return _executar_confirmar_reserva(args, config_negoci)
    elif tool_name == "cancellar_reserva":
        return _executar_cancellar_reserva(args, config_negoci)
    elif tool_name == "modificar_reserva":
        return _executar_modificar_reserva(args, config_negoci)
    else:
        log.error("[TOOL] Tool desconeguda: %s", tool_name)
        return json.dumps({"error": f"Tool '{tool_name}' no reconeguda."}, ensure_ascii=False)


# =====================================
# SYSTEM PROMPT
# =====================================

def _construir_system_prompt(config: Dict[str, Any]) -> str:
    """
    Construeix el system prompt injectant la configuració del negoci.
    Aquest codi està organitzat en dues parts: l'extracció de dades de 
    la base de dades i sota d'això el prompt complet on es pot editar fàcilment.
    """
    
    # =====================================================================
    # 1. EXTRACCIÓ I FORMATACIÓ DE DADES DE LA BASE DE DADES
    # =====================================================================
    config_extra    = config.get("configuracio_extra", {})
    tipus_negoci    = config.get("tipus", "restaurant")
    nom_negoci      = config.get("nom", "el nostre establiment")
    prompt_personalitzat = config.get("prompt_base", "") # Prové de la web
    
    camps_requerits = config.get("camps_requerits", ["nom", "persones", "hora", "data"])
    noms_camps = _extreure_noms_camps(camps_requerits)
    
    # Dates
    avui = date.today()
    nom_dia = avui.strftime("%A")
    dema = (avui + timedelta(days=1)).isoformat()
    avui_str = avui.isoformat()
    
    # Operativa bàsica
    capacitat = config_extra.get("capacitat_maxima", "No definida")
    dies_tancats = config_extra.get("dies_tancats", [])
    dies_tancats_str = ", ".join(dies_tancats) if dies_tancats else "Cap (Obert cada dia)"
    
    # Obtenir l'horari i formatar-lo perquè la IA ho llegeixi perfectament
    horaris = config_extra.get("horaris")
    horaris_str = ""
    if isinstance(horaris, dict):
        dias_ca = {"monday": "Dilluns", "tuesday": "Dimarts", "wednesday": "Dimecres", 
                   "thursday": "Dijous", "friday": "Divendres", "saturday": "Dissabte", "sunday": "Diumenge"}
        for dia_en, hd in horaris.items():
            dia_ca = dias_ca.get(dia_en, dia_en.capitalize())
            if hd.get("closed"):
                horaris_str += f"  - {dia_ca}: TANCAT\n"
            else:
                o = hd.get("open", hd.get("obertura", "00:00"))
                c = hd.get("close", hd.get("tancament", "23:59"))
                horaris_str += f"  - {dia_ca}: de {o} a {c}\n"
    elif isinstance(horaris, list):
        horaris_str = f"  - Hores permeses: {', '.join(str(h) for h in horaris)}\n"
    else:
        horaris_str = f"  - No hi ha horaris específics definits.\n"

    # Camps
    camps_obligatoris_str = ", ".join(noms_camps).upper()

    # =====================================================================
    # 2. DEFINICIÓ DEL PROMPT MESTRE (EDITA A GUST A PARTIR D'AQUÍ)
    # =====================================================================
    PROMPT_MESTRE = f"""Ets l'assistent virtual telefònic exclusiu del negoci '{nom_negoci}' (que és un {tipus_negoci}).

[DADES DEL NEGOCI EN TEMPS REAL]
- Data i hora actuals: {avui_str} (Avui és {nom_dia}). Demà és dia {dema}.
- Per una sola reserva, la capacitat màxima son {capacitat} persones
- Dies tancats de forma general: {dies_tancats_str}
- Horari Habitual d'obertura:
{horaris_str}

[INSTRUCCIONS DE PERSONALITAT (DADES DE L'USUARI / WEB)]
- Parla fent canvis de velocitat i posant petites inflexions d'emoció, mantingues un ritme de la conversa dinàmic i ràpid. No parlis lentament.
{prompt_personalitzat if prompt_personalitzat else "Sigues extremadament amable, directe i fes que la conversa sembli molt natural i humana. Ets resolutiu i el teu to és impecat i pròxim."}

[ELS TEUS OBJECTIUS I COM FUNCIONES]
1. EL TEU OBJECTIU PRINCIPAL és atendre el client.  En cas que truqui per fer una consulta, ajuda'l. Si vol fer una reserva, has de recollir AQUESTS CAMPS EXACTES per fer la reserva, en aquest ordre excepte si el client se t'avança:
>> {camps_obligatoris_str}

2. PROCÉS PAS A PAS (RESERVES):
   - Saluda càlidament.
   - Condueix el client naturalment recollint els camps que faltin.
   - Un cop tinguis TOTES les dades, resumeix la reserva breument (ex: "Perfecte, doncs serien 4 persones per avui a les vuit, oi?") per demanar LA CONFIRMACIÓ FINAL DE L'USUARI.
   - NOMÉS QUANT CONFIRMI: crida la funció 'comprovar_disponibilitat'.
   - Si tens llum verda (disponible=true), executa JUST DESPRÉS 'confirmar_reserva' en silenci, i contesta informant del resultat d'èxit de forma alegre ("Molt bé! Ja teniu la reserva confirmada per a aquesta nit!").
   - Si no hi ha disponibilitat, proposa una altra hora que normalment estigui oberta en els vostres horaris.

3. ALTRES PROCEDIMENTS:
   - MODIFICACIONS: Si un client diu explícitament que vol canviar hora, data o persones d'una reserva ja feta, crida 'modificar_reserva' amb les peticions noves (el sistema buscarà la original automàticament gràcies al seu número).
   - CANCEL·LACIONS: Si vol cancel·lar, simplement crida 'cancellar_reserva' al més aviat possible.

[NORMES D'OR (MOLT IMPORTANT)]
- ETS UN TELÈFON, NO UN XATBOT: Parla en frases EXTREMADAMENT CURTES i dinàmiques.
- RES DE LLISTES: Si algú demana recomanacions d'hora d'obertura, no escupis els 7 dies, simplement digues: "Miri, de dimarts a diumenge obrim pels volts de les 8 i fins mitjanit."
- MAI DONIS DADES REALS ABANS DE COMPROVAR-LES. Tampoc t'inventis el nom del client. Si llegeixes una dada buida, pregunta-la.
- SOROLL DE FONS: A vegades es filtra la veu d'una altra persona, o la ràdio. Si només captes mitges frases sense sentit, espera en silenci o digues "Perdona, amb el soroll no t'he entès bé. Què em deies?".
"""

    return PROMPT_MESTRE

