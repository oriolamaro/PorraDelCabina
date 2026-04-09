from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple

# ==========================================
# 1. CONFIGURACIÓ DE LA PERRUQUERIA
# ==========================================

# Quants clients podem atendre ALHORA (ex: tenim 3 perruquers/cadires)
CAPACITAT_SIMULTANIA = 3

# Diccionari amb els tipus de servei i la seva durada en MINUTS
CATALEG_SERVEIS = {
    "tall_home": 30,
    "tall_dona": 45,
    "tint": 120,
    "metxes": 150,
    "rentar_i_assecar": 30,
    "afaitat": 20
}

# ==========================================
# 2. LÒGICA DE TEMPS I CAPACITAT
# ==========================================

def text_a_datetime(hora_str: str) -> datetime:
    """Converteix un text 'HH:MM' a un objecte datetime usable per fer càlculs."""
    return datetime.strptime(hora_str, "%H:%M")

def calcular_ocupacio_maxima(inici_req: datetime, fi_req: datetime, reserves_confirmades: List[Dict[str, Any]]) -> int:
    """
    Calcula quantes persones hi haurà ateses AL MATEIX TEMPS durant la franja que volem reservar.
    Ho fa comprovant l'ocupació minut a minut per ser 100% precís.
    """
    max_clients_simultanis = 0
    temps_actual = inici_req
    
    # Pre-calculem els inicis i finals de les reserves existents per eficiència
    intervals_ocupats = []
    for r in reserves_confirmades:
        inici_r = text_a_datetime(r["hora_inici"])
        fi_r = text_a_datetime(r["hora_fi"])
        intervals_ocupats.append((inici_r, fi_r))

    # Escombrem des del minut d'inici fins al minut final de la reserva desitjada
    while temps_actual < fi_req:
        clients_en_aquest_minut = 0
        
        for inici_r, fi_r in intervals_ocupats:
            # Si el minut actual està dins de l'interval d'una reserva existent (inclusiu l'inici, exclusiu el final)
            if inici_r <= temps_actual < fi_r:
                clients_en_aquest_minut += 1
                
        if clients_en_aquest_minut > max_clients_simultanis:
            max_clients_simultanis = clients_en_aquest_minut
            
        # Avancem 5 minuts (granulació suficient per perruqueries i molt més ràpid d'executar)
        temps_actual += timedelta(minutes=5)
        
    return max_clients_simultanis

# ==========================================
# 3. EL PROCESSADOR DE RESERVES
# ==========================================

def processar_reserves_perruqueria(peticions: List[Dict[str, Any]], estat_actual_reserves: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Rep una llista de peticions i avalua si hi ha prou personal/cadires per atendre'ls.
    """
    acceptades = []
    rebutjades = []
    
    # Treballem amb una còpia dinàmica per poder avaluar peticions que entren de cop
    reserves_simulades = estat_actual_reserves.copy()
    
    for peticio in peticions:
        nom = peticio.get("nom", "Anònim")
        servei = peticio.get("servei")
        hora_inici_str = peticio.get("hora_inici")
        
        # Validacions de seguretat
        if servei not in CATALEG_SERVEIS:
            peticio["motiu"] = f"El servei '{servei}' no existeix al catàleg."
            rebutjades.append(peticio)
            continue
            
        try:
            inici_req = text_a_datetime(hora_inici_str)
        except ValueError:
            peticio["motiu"] = "Format d'hora incorrecte. Utilitza HH:MM."
            rebutjades.append(peticio)
            continue

        # Calculem l'hora de finalització sumant els minuts del servei
        durada_minuts = CATALEG_SERVEIS[servei]
        fi_req = inici_req + timedelta(minutes=durada_minuts)
        hora_fi_str = fi_req.strftime("%H:%M")
        
        # Comprovem quina serà l'ocupació si acceptem aquesta reserva
        ocupacio = calcular_ocupacio_maxima(inici_req, fi_req, reserves_simulades)
        
        if ocupacio < CAPACITAT_SIMULTANIA:
            # ACCEPTADA: Hi ha espai (cadires/personal) disponible durant tota l'estona
            reserva_confirmada = {
                "nom": nom,
                "servei": servei,
                "durada": durada_minuts,
                "hora_inici": hora_inici_str,
                "hora_fi": hora_fi_str,
                "motiu": "Assignació correcta"
            }
            acceptades.append(reserva_confirmada)
            reserves_simulades.append(reserva_confirmada)
        else:
            # REBUTJADA: Superaríem el límit de clients alhora en algun moment
            peticio["motiu"] = f"A les {hora_inici_str} ja tenim {CAPACITAT_SIMULTANIA} clients atesos alhora. Intenta-ho en una altra franja."
            rebutjades.append(peticio)

    return acceptades, rebutjades

# ==========================================
# PROVA DE RENDIMENT I ROBUSTESA
# ==========================================
if __name__ == "__main__":
    
    # Imaginem que ja tenim 2 clients reservats a la BBDD a les 10:00h
    reserves_bbdd = [
        {"nom": "Anna", "servei": "tint", "hora_inici": "10:00", "hora_fi": "12:00"}, # Ocupa fins les 12:00
        {"nom": "Marc", "servei": "tall_home", "hora_inici": "10:00", "hora_fi": "10:30"} # Ocupa fins les 10:30
    ]
    
    # Noves peticions
    peticions = [
        # Ocuparia la 3a i última cadira de 10:00 a 10:45. Hauria d'entrar.
        {"nom": "Laura", "servei": "tall_dona", "hora_inici": "10:00"}, 
        
        # REBUTJADA: Intentaria ser el 4t client de 10:15 a 10:45. Supera la capacitat.
        {"nom": "Pol", "servei": "tall_home", "hora_inici": "10:15"},
        
        # ACCEPTADA: A les 10:30 en Marc marxa. Queda una cadira lliure fins a les 11:00.
        {"nom": "Jordi", "servei": "tall_home", "hora_inici": "10:30"} 
    ]
    
    print(f"--- SIMULADOR DE RESERVES (Capacitat Màxima: {CAPACITAT_SIMULTANIA} alhora) ---")
    
    acc, reb = processar_reserves_perruqueria(peticions, reserves_bbdd)
    
    print("\n✅ RESERVES ACCEPTADES:")
    for r in acc:
        print(f" - {r['nom']} | {r['servei']} ({r['durada']}m) | {r['hora_inici']} -> {r['hora_fi']}")
        
    print("\n❌ RESERVES REBUTJADES:")
    for r in reb:
        print(f" - {r.get('nom')} | {r.get('servei')} | {r.get('hora_inici')} | Motiu: {r.get('motiu')}")