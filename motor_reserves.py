"""
Motor de Reserves — Dispatcher central per tipus de negoci.

Cada negoci té un 'tipus_negoci' a Supabase (ex: "restaurant", "perruqueria").
Aquest mòdul enruta la reserva a l'algorisme correcte automàticament.
"""

from typing import Dict, Any, List, Tuple

from algorisme_taules import processar_llista_reserves as _motor_restaurant
from algorisme_perruqueries import processar_reserves_perruqueria as _motor_perruqueria


# ==========================================
# ADAPTADORS (unifiquen la signatura)
# ==========================================

def _adaptar_restaurant(
    info_client: Dict[str, Any],
    reserves_actuals: List[Dict[str, Any]],
    config_extra: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Adapta l'algorisme de restaurants a la interfície universal."""
    return _motor_restaurant([info_client], reserves_actuals, config_extra)


def _adaptar_perruqueria(
    info_client: Dict[str, Any],
    reserves_actuals: List[Dict[str, Any]],
    config_extra: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Adapta l'algorisme de perruqueries a la interfície universal."""
    return _motor_perruqueria([info_client], reserves_actuals)


# ==========================================
# REGISTRE DE MOTORS
# ==========================================

MOTORS = {
    "restaurant": _adaptar_restaurant,
    "perruqueria": _adaptar_perruqueria,
}


# ==========================================
# FUNCIÓ PÚBLICA
# ==========================================

def processar_reserva(
    tipus_negoci: str,
    info_client: Dict[str, Any],
    reserves_actuals: List[Dict[str, Any]],
    config_extra: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Punt d'entrada universal per processar una reserva.
    
    Args:
        tipus_negoci: "restaurant", "perruqueria", etc.
        info_client: Dades de la reserva (nom, hora, persones, etc.)
        reserves_actuals: Reserves ja confirmades al sistema
        config_extra: Configuració específica del negoci (mapa_taules, etc.)
    
    Returns:
        Tuple de (acceptades, rebutjades)
    """
    motor = MOTORS.get(tipus_negoci.lower().strip() if tipus_negoci else "")
    
    if not motor:
        tipus_suportats = ", ".join(MOTORS.keys())
        return [], [{
            **info_client,
            "motiu": f"Tipus de negoci '{tipus_negoci}' no suportat. Tipus vàlids: {tipus_suportats}"
        }]
    
    try:
        return motor(info_client, reserves_actuals, config_extra)
    except Exception as e:
        print(f"[ERROR MOTOR] Error processant reserva ({tipus_negoci}): {e}")
        return [], [{
            **info_client,
            "motiu": f"Error intern processant la reserva: {str(e)}"
        }]
