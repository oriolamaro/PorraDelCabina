from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Set, FrozenSet
from collections import deque

# ==========================================
# 1. LÒGICA D'ESPAI (Capacitat i Unions)
# ==========================================

def calcular_capacitat_individual(taula: Dict[str, Any]) -> int:
    """Calcula la capacitat d'una taula de forma segura."""
    # Prioritzar dades per-costat si existeixen (nou format visual)
    top = taula.get("top_seats")
    bottom = taula.get("bottom_seats")
    left = taula.get("left_seats")
    right = taula.get("right_seats")
    
    if top is not None and bottom is not None and left is not None and right is not None:
        return top + bottom + left + right
    
    # Format clàssic
    places_lat = taula.get("places_laterals", 0)
    caps = taula.get("caps_de_taula", 0)
    
    if places_lat > 0 or caps > 0:
        return places_lat + caps
    
    return taula.get("capacitat", 0)


def _determinar_costat_unio(taula_a: Dict[str, Any], taula_b: Dict[str, Any]) -> Tuple[str, str]:
    """
    Determina quins costats de dues taules s'enfronten, basant-se en les seves posicions (x, y).
    
    Retorna (costat_de_A, costat_de_B).
    Exemples:
      - B a la dreta de A → ('right', 'left')
      - B a sota de A    → ('bottom', 'top')
    """
    xa = taula_a.get("x", 0)
    ya = taula_a.get("y", 0)
    xb = taula_b.get("x", 0)
    yb = taula_b.get("y", 0)
    
    dx = xb - xa
    dy = yb - ya
    
    # Si estan exactament al mateix punt, assumim horitzontal per defecte
    if dx == 0 and dy == 0:
        return ("right", "left")
    
    if abs(dx) >= abs(dy):
        # Predominantment horitzontal
        if dx >= 0:
            return ("right", "left")   # B és a la dreta de A
        else:
            return ("left", "right")   # B és a l'esquerra de A
    else:
        # Predominantment vertical
        if dy >= 0:
            return ("bottom", "top")   # B és a sota de A
        else:
            return ("top", "bottom")   # B és a dalt de A


def _seients_costat(taula: Dict[str, Any], costat: str) -> int:
    """
    Retorna el nombre de seients que hi ha en un costat específic d'una taula.
    
    Per taules rodones (forma='circle'): retorna 1 per connexió (estimació conservadora).
    Per taules rectangulars: utilitza les dades per-costat si existeixen,
    o dedueix dels camps clàssics (places_laterals / caps_de_taula).
    """
    forma = taula.get("forma", "rectangle")
    
    if forma == "circle":
        # Les taules rodones no tenen "costats" — cada connexió bloqueja
        # aproximadament 1 cadira (la que queda contra l'altra taula)
        return 1
    
    # Dades per-costat (format nou)
    mapa_claus = {
        "top": "top_seats",
        "bottom": "bottom_seats",
        "left": "left_seats",
        "right": "right_seats",
    }
    clau = mapa_claus.get(costat)
    if clau and clau in taula:
        return taula[clau]
    
    # Fallback: deduir dels camps clàssics (places_laterals = amunt + avall, caps_de_taula = esq + dreta)
    if costat in ("left", "right"):
        caps = taula.get("caps_de_taula", 0)
        # Si no hi ha caps, no hi ha cadires als laterals estrets → 0 perduts
        if caps <= 0:
            return 0
        # Dividim equitativament entre esquerra i dreta
        return caps // 2 if costat == "left" else (caps + 1) // 2
    else:  # "top" o "bottom"
        lats = taula.get("places_laterals", 0)
        if lats <= 0:
            return 0
        return lats // 2 if costat == "top" else (lats + 1) // 2


def calcular_capacitat_real_grup(taules_grup: List[Dict[str, Any]]) -> int:
    """
    Calcula la capacitat real d'un grup de taules ajuntades.
    
    ALGORISME ESPACIAL (nou):
      Per cada parell de taules veïnes dins del grup, utilitza les seves
      posicions (x, y) per determinar quin costat de cada taula queda
      contra l'altra. Els seients d'aquests costats es resten perquè
      les cadires no hi caben físicament.
    
    FALLBACK (compatibilitat):
      Si les taules no tenen posicions (x, y), utilitza l'heurística
      clàssica: cada unió perd 2 "caps de taula".
    
    Exemples:
      T1(dreta:1) ← → T2(esquerra:1)  →  perd 2 seients
      T1(dreta:0) ← → T2(esquerra:0)  →  perd 0 seients (perfecte per taules llargues)
      Rodona ← → Rectangular(esq:1)   →  perd 2 seients (1+1)
    """
    if not taules_grup:
        return 0
    if len(taules_grup) == 1:
        return calcular_capacitat_individual(taules_grup[0])
    
    taula_per_id: Dict[str, Dict[str, Any]] = {}
    for t in taules_grup:
        tid = t.get("id")
        if tid:
            taula_per_id[tid] = t
    ids_grup = set(taula_per_id.keys())
    
    suma_bruta = sum(calcular_capacitat_individual(t) for t in taules_grup)
    
    # Comprovar si tenim coordenades de posició
    te_posicions = all("x" in t and "y" in t for t in taules_grup)
    
    if not te_posicions:
        # ─── FALLBACK CLÀSSIC ───
        # Cada unió perd 2 "caps de taula" (1 per banda)
        unions = len(taules_grup) - 1
        total_caps = sum(t.get("caps_de_taula", 0) for t in taules_grup)
        caps_consumits = min(unions * 2, total_caps)
        return max(0, suma_bruta - caps_consumits)
    
    # ─── ALGORISME ESPACIAL ───
    # Per cada parell de veïnes dins del grup, calcular pèrdua exacta
    seients_perduts = 0
    parells_comptats: Set[Tuple[str, str]] = set()
    
    for taula in taules_grup:
        tid = taula.get("id")
        if not tid:
            continue
        veines = taula.get("veines", [])
        if not isinstance(veines, list):
            continue
        
        for vid in veines:
            # Ignorar veïnes que no formen part d'aquest grup
            if vid not in ids_grup:
                continue
            
            # Evitar comptar el mateix parell dues vegades
            parell = (min(tid, vid), max(tid, vid))
            if parell in parells_comptats:
                continue
            parells_comptats.add(parell)
            
            taula_b = taula_per_id[vid]
            costat_a, costat_b = _determinar_costat_unio(taula, taula_b)
            
            perduts_a = _seients_costat(taula, costat_a)
            perduts_b = _seients_costat(taula_b, costat_b)
            
            seients_perduts += perduts_a + perduts_b
    
    return max(0, suma_bruta - seients_perduts)


# ==========================================
# 2. LÒGICA DE TEMPS (Filtre d'Horaris)
# ==========================================

def hores_solapen(hora_str_1: str, hora_str_2: str, durada_torn: int) -> bool:
    """Comprova si dues franges horàries s'encavalquen."""
    try:
        inici_1 = datetime.strptime(hora_str_1, "%H:%M")
        inici_2 = datetime.strptime(hora_str_2, "%H:%M")
    except (ValueError, TypeError):
        return False 
        
    fi_1 = inici_1 + timedelta(minutes=durada_torn)
    fi_2 = inici_2 + timedelta(minutes=durada_torn)
    
    return max(inici_1, inici_2) < min(fi_1, fi_2)


def obtenir_taules_lliures(
    hora_desitjada: str, 
    reserves_confirmades: List[Dict[str, Any]], 
    mapa_taules: List[Dict[str, Any]], 
    durada_torn: int
) -> List[Dict[str, Any]]:
    """Retorna la llista de taules que NO estan bloquejades a l'hora desitjada."""
    taules_ocupades_ids: Set[str] = set()
    
    for reserva in reserves_confirmades:
        if hores_solapen(hora_desitjada, reserva.get("hora", "00:00"), durada_torn):
            for taula_id in reserva.get("taules_assignades", []):
                taules_ocupades_ids.add(taula_id)
                
    return [t for t in mapa_taules if t.get("id") not in taules_ocupades_ids]


# ==========================================
# 3. ASSIGNACIÓ ÒPTIMA (BFS sobre Graf de Veïnatge)
# ==========================================

def _construir_graf_veines(taules_lliures: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Construeix un graf d'adjacència bidireccional a partir de les taules lliures.
    Només inclou arestes cap a taules que realment estan a la llista de lliures.
    """
    ids_lliures = {t.get("id") for t in taules_lliures if t.get("id")}
    graf: Dict[str, List[str]] = {tid: [] for tid in ids_lliures}
    
    for taula in taules_lliures:
        tid = taula.get("id")
        if not tid:
            continue
        veines = taula.get("veines", [])
        if isinstance(veines, list):
            for vid in veines:
                if vid in ids_lliures and vid != tid:
                    if vid not in graf[tid]:
                        graf[tid].append(vid)
                    if tid not in graf.get(vid, []):
                        graf.setdefault(vid, []).append(tid)
    
    return graf


def _trobar_grups_connexos_bfs(
    taula_inici: str,
    graf: Dict[str, List[str]],
    max_mida: int
) -> List[FrozenSet[str]]:
    """
    BFS des d'una taula, generant tots els subconjunts connexos de mida 1..max_mida.
    """
    resultats: List[FrozenSet[str]] = []
    cua: deque[FrozenSet[str]] = deque()
    grup_inicial = frozenset([taula_inici])
    cua.append(grup_inicial)
    
    visitats: Set[FrozenSet[str]] = {grup_inicial}
    resultats.append(grup_inicial)
    
    while cua:
        grup_actual = cua.popleft()
        
        if len(grup_actual) >= max_mida:
            continue
        
        veines_candidates: Set[str] = set()
        for membre in grup_actual:
            for veina in graf.get(membre, []):
                if veina not in grup_actual:
                    veines_candidates.add(veina)
        
        for candidata in veines_candidates:
            nou_grup = grup_actual | frozenset([candidata])
            if nou_grup not in visitats:
                visitats.add(nou_grup)
                resultats.append(nou_grup)
                cua.append(nou_grup)
    
    return resultats


def buscar_millor_assignacio(
    persones: int, 
    taules_lliures: List[Dict[str, Any]],
    max_taules_ajuntables: int = 4
) -> Optional[List[str]]:
    """
    Busca l'assignació que deixi menys cadires buides.
    Utilitza BFS sobre el graf de veïnatge per trobar TOTS els grups
    connexos possibles de mida 1..max_taules_ajuntables.
    """
    if not taules_lliures or persones <= 0:
        return None
    
    taula_per_id: Dict[str, Dict[str, Any]] = {}
    for t in taules_lliures:
        tid = t.get("id")
        if tid:
            taula_per_id[tid] = t
    
    graf = _construir_graf_veines(taules_lliures)
    
    tots_els_grups: Set[FrozenSet[str]] = set()
    for tid in taula_per_id:
        grups = _trobar_grups_connexos_bfs(tid, graf, max_taules_ajuntables)
        tots_els_grups.update(grups)
    
    millor_opcio: Optional[List[str]] = None
    menys_cadires_buides = float('inf')
    
    for grup_ids in tots_els_grups:
        grup_taules = [taula_per_id[tid] for tid in grup_ids if tid in taula_per_id]
        capacitat = calcular_capacitat_real_grup(grup_taules)
        
        if capacitat >= persones:
            cadires_buides = capacitat - persones
            
            if (cadires_buides < menys_cadires_buides or 
                (cadires_buides == menys_cadires_buides and 
                 millor_opcio is not None and 
                 len(grup_ids) < len(millor_opcio))):
                menys_cadires_buides = cadires_buides
                millor_opcio = sorted(list(grup_ids))
    
    return millor_opcio


# ==========================================
# 4. PROCESSADOR DE RESERVES (Universal)
# ==========================================

def processar_llista_reserves(
    solicituds_entrants: List[Dict[str, Any]], 
    estat_actual_reserves: List[Dict[str, Any]], 
    config_extra: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Processa una llista de sol·licituds de reserva contra l'estat actual.
    Retorna (acceptades, rebutjades).
    """
    acceptades = []
    rebutjades = []
    
    mapa_taules = config_extra.get("mapa_taules", [])
    durada_torn = config_extra.get("durada_torn_minuts", 120)
    max_ajuntables = config_extra.get("max_taules_ajuntables", 4)
    
    if not mapa_taules:
        for peticio in solicituds_entrants:
            peticio["motiu"] = "El negoci no té mapa de taules configurat."
            rebutjades.append(peticio)
        return acceptades, rebutjades
    
    reserves_simulades = estat_actual_reserves.copy()
    
    for peticio in solicituds_entrants:
        nom = peticio.get("nom", "Client Anònim")
        pax = peticio.get("persones", 0)
        hora = peticio.get("hora", "00:00")
        
        if pax <= 0:
            peticio["motiu"] = "El nombre de persones ha de ser superior a 0."
            rebutjades.append(peticio)
            continue
        
        taules_lliures = obtenir_taules_lliures(hora, reserves_simulades, mapa_taules, durada_torn)
        taules_assignades = buscar_millor_assignacio(pax, taules_lliures, max_ajuntables)
        
        if taules_assignades:
            reserva_confirmada = {
                "nom": nom,
                "persones": pax,
                "hora": hora,
                "data": peticio.get("data"),
                "taules_assignades": taules_assignades,
                "motiu": "Assignació correcta"
            }
            acceptades.append(reserva_confirmada)
            reserves_simulades.append(reserva_confirmada)
        else:
            peticio["motiu"] = "No hi ha capacitat o combinació de taules possible a aquesta hora."
            rebutjades.append(peticio)
            
    return acceptades, rebutjades


# ==========================================
# 5. TESTS INTEGRATS
# ==========================================

if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    
    print("=" * 60)
    print("TESTS AMB FORMAT CLASSIC (sense posicions)")
    print("=" * 60)
    
    mapa_classic = [
        {"id": "T1", "capacitat": 4, "places_laterals": 2, "caps_de_taula": 2, "veines": ["T2"]},
        {"id": "T2", "capacitat": 4, "places_laterals": 2, "caps_de_taula": 2, "veines": ["T1", "T3"]},
        {"id": "T3", "capacitat": 6, "places_laterals": 4, "caps_de_taula": 2, "veines": ["T2"]},
        {"id": "T4", "capacitat": 2, "places_laterals": 0, "caps_de_taula": 2, "veines": []},
    ]
    config_classic = {"mapa_taules": mapa_classic, "durada_torn_minuts": 90, "max_taules_ajuntables": 3}
    
    print("\n[CLASSIC] Test 1: Taula individual (2 persones)")
    acc, reb = processar_llista_reserves(
        [{"nom": "Anna", "persones": 2, "hora": "21:00"}], [], config_classic
    )
    assert len(acc) == 1, "ERROR: Hauria de ser acceptat!"
    print(f"  OK -> Taules: {acc[0]['taules_assignades']}")
    
    print("[CLASSIC] Test 2: 7 persones -> ajuntar 2 taules")
    acc, reb = processar_llista_reserves(
        [{"nom": "Marc", "persones": 7, "hora": "21:00"}], [], config_classic
    )
    assert len(acc) == 1, "ERROR: Hauria de combinar 2 taules!"
    print(f"  OK -> Taules: {acc[0]['taules_assignades']}")
    
    print("[CLASSIC] Test 3: 10 persones -> ajuntar 3 taules")
    acc, reb = processar_llista_reserves(
        [{"nom": "Laura", "persones": 10, "hora": "21:00"}], [], config_classic
    )
    assert len(acc) == 1, "ERROR: Hauria de combinar 3 taules!"
    print(f"  OK -> Taules: {acc[0]['taules_assignades']}")
    
    print("[CLASSIC] Test 4: 20 persones -> rebuig")
    acc, reb = processar_llista_reserves(
        [{"nom": "Pol", "persones": 20, "hora": "21:00"}], [], config_classic
    )
    assert len(reb) == 1, "ERROR: Hauria de rebutjar!"
    print(f"  OK -> Motiu: {reb[0].get('motiu')}")
    
    print("[CLASSIC] Test 5: Capacitat grup T1+T2 = 4+4 - 2 = 6")
    cap = calcular_capacitat_real_grup([mapa_classic[0], mapa_classic[1]])
    assert cap == 6, f"ERROR: cap={cap}, expected 6"
    print(f"  OK -> Capacitat: {cap}")
    
    print("[CLASSIC] Test 6: 2 persones -> T4 (menys buides)")
    acc, reb = processar_llista_reserves(
        [{"nom": "Maria", "persones": 2, "hora": "21:00"}], [], config_classic
    )
    assert acc[0]["taules_assignades"] == ["T4"], f"ERROR: Expected T4, got {acc[0]['taules_assignades']}"
    print(f"  OK -> Taules: {acc[0]['taules_assignades']}")
    
    print("\n" + "=" * 60)
    print("TESTS AMB FORMAT ESPACIAL (posicions + seients per costat)")
    print("=" * 60)
    
    # Escenari: Restaurant amb taules rectangulars i rodones
    # T1 i T2 estan en fila horitzontal (T1 a l'esquerra, T2 a la dreta)
    # T3 està a sota de T2
    # T5 és una taula llarga (bench) sense caps → ajuntar-la NO perd seients laterals
    # T6 és rodona
    
    mapa_espacial = [
        {
            "id": "T1", "forma": "rectangle", "x": 100, "y": 100,
            "top_seats": 1, "bottom_seats": 1, "left_seats": 1, "right_seats": 1,
            "capacitat": 4, "places_laterals": 2, "caps_de_taula": 2,
            "veines": ["T2"]
        },
        {
            "id": "T2", "forma": "rectangle", "x": 240, "y": 100,
            "top_seats": 1, "bottom_seats": 1, "left_seats": 1, "right_seats": 1,
            "capacitat": 4, "places_laterals": 2, "caps_de_taula": 2,
            "veines": ["T1", "T3"]
        },
        {
            "id": "T3", "forma": "rectangle", "x": 240, "y": 260,
            "top_seats": 2, "bottom_seats": 2, "left_seats": 1, "right_seats": 1,
            "capacitat": 6, "places_laterals": 4, "caps_de_taula": 2,
            "veines": ["T2"]
        },
        {
            "id": "T4", "forma": "rectangle", "x": 500, "y": 100,
            "top_seats": 1, "bottom_seats": 1, "left_seats": 0, "right_seats": 0,
            "capacitat": 2, "places_laterals": 2, "caps_de_taula": 0,
            "veines": []
        },
        {
            # Taula "bench" llarga: 3 amunt, 3 avall, SENSE caps laterals
            # Ideal per ajuntar: no perd seients!
            "id": "T5", "forma": "rectangle", "x": 500, "y": 260,
            "top_seats": 3, "bottom_seats": 3, "left_seats": 0, "right_seats": 0,
            "capacitat": 6, "places_laterals": 6, "caps_de_taula": 0,
            "veines": ["T6"]
        },
        {
            "id": "T6", "forma": "rectangle", "x": 640, "y": 260,
            "top_seats": 3, "bottom_seats": 3, "left_seats": 0, "right_seats": 0,
            "capacitat": 6, "places_laterals": 6, "caps_de_taula": 0,
            "veines": ["T5"]
        },
    ]
    config_espacial = {"mapa_taules": mapa_espacial, "durada_torn_minuts": 90, "max_taules_ajuntables": 4}
    
    # --- Test espacial: capacitats individuals ---
    print("\n[ESPACIAL] Test 7: Capacitat individual amb dades per-costat")
    for t in mapa_espacial:
        cap = calcular_capacitat_individual(t)
        expected = t["top_seats"] + t["bottom_seats"] + t["left_seats"] + t["right_seats"]
        assert cap == expected, f"ERROR: {t['id']} cap={cap}, expected {expected}"
    print("  OK -> Totes les capacitats individuals correctes")
    
    # --- Test espacial: T1+T2 horitzontal ---
    print("[ESPACIAL] Test 8: T1+T2 horitzontal (perd right_1 + left_1 = 2)")
    cap = calcular_capacitat_real_grup([mapa_espacial[0], mapa_espacial[1]])
    # T1(4) + T2(4) - T1.right(1) - T2.left(1) = 6
    assert cap == 6, f"ERROR: cap={cap}, expected 6"
    print(f"  OK -> Capacitat: {cap}")
    
    # --- Test espacial: T2+T3 vertical ---
    print("[ESPACIAL] Test 9: T2+T3 vertical (perd bottom_1 + top_2 = 3)")
    cap = calcular_capacitat_real_grup([mapa_espacial[1], mapa_espacial[2]])
    # T2(4) + T3(6) - T2.bottom(1) - T3.top(2) = 7
    assert cap == 7, f"ERROR: cap={cap}, expected 7"
    print(f"  OK -> Capacitat: {cap}")
    
    # --- Test espacial: T5+T6 bench (0 caps -> 0 perduts!) ---
    print("[ESPACIAL] Test 10: T5+T6 bench sense caps (perd 0+0 = 0!)")
    cap = calcular_capacitat_real_grup([mapa_espacial[4], mapa_espacial[5]])
    # T5(6) + T6(6) - T5.right(0) - T6.left(0) = 12
    assert cap == 12, f"ERROR: cap={cap}, expected 12"
    print(f"  OK -> Capacitat: {cap} (tot aprofitat!)")
    
    # --- Test espacial: 3 taules T1+T2+T3 ---
    print("[ESPACIAL] Test 11: T1+T2+T3 cadena (2 unions)")
    cap = calcular_capacitat_real_grup([mapa_espacial[0], mapa_espacial[1], mapa_espacial[2]])
    # T1(4) + T2(4) + T3(6) = 14
    # Unió T1-T2: T1.right(1) + T2.left(1) = 2
    # Unió T2-T3: T2.bottom(1) + T3.top(2) = 3
    # Total perduts = 5 -> Capacitat = 14 - 5 = 9
    assert cap == 9, f"ERROR: cap={cap}, expected 9"
    print(f"  OK -> Capacitat: {cap}")
    
    # --- Test espacial: assignació 2 persones -> T4 (exacte, 0 buides) ---
    print("[ESPACIAL] Test 12: 2 persones -> T4 (cap. 2, 0 buides)")
    acc, reb = processar_llista_reserves(
        [{"nom": "Joan", "persones": 2, "hora": "21:00"}], [], config_espacial
    )
    assert len(acc) == 1
    assert acc[0]["taules_assignades"] == ["T4"], f"ERROR: Expected T4, got {acc[0]['taules_assignades']}"
    print(f"  OK -> Taules: {acc[0]['taules_assignades']}")
    
    # --- Test espacial: 12 persones -> T5+T6 (cap. 12, 0 buides! millor que qualsevol altra combinació) ---
    print("[ESPACIAL] Test 13: 12 persones -> T5+T6 bench (12 places, 0 buides)")
    acc, reb = processar_llista_reserves(
        [{"nom": "Grup Gran", "persones": 12, "hora": "21:00"}], [], config_espacial
    )
    assert len(acc) == 1
    assert acc[0]["taules_assignades"] == ["T5", "T6"], f"ERROR: Expected T5+T6, got {acc[0]['taules_assignades']}"
    print(f"  OK -> Taules: {acc[0]['taules_assignades']}")
    
    # --- Test espacial: 11 persones -> T5+T6 (cap. 12, 1 buida) ---
    print("[ESPACIAL] Test 14: 11 persones -> T5+T6 bench (12 places, 1 buida)")
    acc, reb = processar_llista_reserves(
        [{"nom": "Grup 11", "persones": 11, "hora": "21:00"}], [], config_espacial
    )
    assert len(acc) == 1
    assert acc[0]["taules_assignades"] == ["T5", "T6"], f"ERROR: Expected T5+T6, got {acc[0]['taules_assignades']}"
    print(f"  OK -> Taules: {acc[0]['taules_assignades']}")
    
    # --- Test rodona ---
    print("\n[ESPACIAL] Test 15: Taula rodona amb rectangular")
    mapa_rodona = [
        {
            "id": "R1", "forma": "circle", "x": 100, "y": 100,
            "capacitat": 6, "top_seats": 0, "bottom_seats": 0, "left_seats": 0, "right_seats": 0,
            "places_laterals": 6, "caps_de_taula": 0,
            "veines": ["R2"]
        },
        {
            "id": "R2", "forma": "rectangle", "x": 240, "y": 100,
            "top_seats": 2, "bottom_seats": 2, "left_seats": 1, "right_seats": 1,
            "capacitat": 6, "places_laterals": 4, "caps_de_taula": 2,
            "veines": ["R1"]
        },
    ]
    cap = calcular_capacitat_real_grup(mapa_rodona)
    # R1(circle, cap 6) + R2(6) = 12
    # Unió: R1.right(circle→1) + R2.left(1) = 2
    # Capacitat = 12 - 2 = 10
    assert cap == 10, f"ERROR: cap={cap}, expected 10"
    print(f"  OK -> Capacitat: {cap}")
    
    # --- Test dues rodones ---
    print("[ESPACIAL] Test 16: Dues taules rodones")
    mapa_2rodones = [
        {
            "id": "C1", "forma": "circle", "x": 100, "y": 100,
            "capacitat": 4, "top_seats": 0, "bottom_seats": 0, "left_seats": 0, "right_seats": 0,
            "places_laterals": 4, "caps_de_taula": 0,
            "veines": ["C2"]
        },
        {
            "id": "C2", "forma": "circle", "x": 200, "y": 100,
            "capacitat": 4, "top_seats": 0, "bottom_seats": 0, "left_seats": 0, "right_seats": 0,
            "places_laterals": 4, "caps_de_taula": 0,
            "veines": ["C1"]
        },
    ]
    cap = calcular_capacitat_real_grup(mapa_2rodones)
    # C1(4) + C2(4) = 8, pèrdua = 1+1 = 2 → 6
    assert cap == 6, f"ERROR: cap={cap}, expected 6"
    print(f"  OK -> Capacitat: {cap}")
    
    print("\n" + "=" * 60)
    print("TOTS ELS TESTS HAN PASSAT CORRECTAMENT!")
    print("=" * 60)