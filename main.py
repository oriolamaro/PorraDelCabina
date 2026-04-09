import os
import json
import asyncio
import websockets
from fastapi import FastAPI, Request, WebSocket, Response, Form
from dotenv import load_dotenv

# Import actions from functional agent
from funcions_agent import generar_tools, _construir_system_prompt, executar_tool
from base_dades import obtenir_dades_negoci

load_dotenv()
app = FastAPI()

# Ara fem servir la clau d'OpenAI
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# URL del WebSocket d'OpenAI (versió Realtime)
OPENAI_URL = "wss://api.openai.com/v1/realtime?model=gpt-realtime-mini-2025-12-15"

@app.get("/")
async def get():
    return {"status": "Servidor operatiu", "openai_key": "OK" if OPENAI_API_KEY else "FALTA"}

@app.post("/voice")
async def handle_voice_inbound(request: Request, From: str = Form(default="Desconegut")):
    caller_number = From
    print(f"📞 [TWILIO] Trucada entrant a /voice de {caller_number}", flush=True)
    host = request.url.netloc 
    
    # Passem el telèfon com a paràmetre al WebSocket stream
    twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
    <Response>
        <Connect>
            <Stream url="wss://{host}/media-stream">
                <Parameter name="telefon" value="{caller_number}" />
            </Stream>
        </Connect>
    </Response>"""
    return Response(content=twiml, media_type="application/xml")

@app.websocket("/media-stream")
async def media_stream(twilio_ws: WebSocket):
    await twilio_ws.accept()
    print("🚀 [WEBSOCKET] Connexió acceptada amb Twilio", flush=True)

    if not OPENAI_API_KEY:
        print("❌ [ERROR] No s'ha trobat OPENAI_API_KEY", flush=True)
        await twilio_ws.close()
        return

    # Obtenir configuració de negoci de la base de dades (sense bloquejar el loop)
    slug_negoci = "sabo";  #  El negoci pel que actua l'agent es definaix aqui
    config_negoci = await asyncio.to_thread(obtenir_dades_negoci, slug_negoci)

    if not config_negoci:
        print(f"❌ [ERROR] No s'ha trobat cap negoci amb l'ID '{slug_negoci}' a Supabase.", flush=True)
        await twilio_ws.close()
        return

    camps_requerits = config_negoci.get("camps_requerits", ["nom", "persones", "hora", "data"])
    system_prompt = _construir_system_prompt(config_negoci)

    # Generar les tools dinàmicament basant-se en els camps del negoci
    tools_negoci = generar_tools(camps_requerits)

    # Convertir l'estructura de les TOOLS del bot de text per a Realtime API
    realtime_tools = []
    for tool in tools_negoci:
        if tool.get("type") == "function":
            f_data = tool.get("function", {})
            realtime_tools.append({
                "type": "function",
                "name": f_data.get("name"),
                "description": f_data.get("description"),
                "parameters": f_data.get("parameters")
            })

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "OpenAI-Beta": "realtime=v1"
    }

    # Connectem amb OpenAI
    async with websockets.connect(OPENAI_URL, additional_headers=headers) as openai_ws:
        print(f"🧠 [OPENAI] Connectat al Cervell (Realtime API) com {slug_negoci}", flush=True)

        # --------------------------------------------------------
        # EL CERVELL: Aquí defineixes com es comporta la teva IA
        # --------------------------------------------------------
        session_update = {
            "type": "session.update",
            "session": {
                "instructions": system_prompt,
                "voice": "verse", # Haurem de poder triar entre 'shimmer', 'verse', 'alloy', 'coral', 'ballad', 'echo', 'shade' i 'ash'.
                "input_audio_format": "g711_ulaw", # El format exacte de Twilio!
                "output_audio_format": "g711_ulaw",
                "modalities": ["audio", "text"],
                "turn_detection": {
                    "type": "server_vad",
                    "threshold": 0.9, 
                    "prefix_padding_ms": 300,
                    "silence_duration_ms": 350, 
                    "create_response": False
                },
                "input_audio_transcription": {
                    "model": "whisper-1" # Per poder llegir a la consola què ha dit l'usuari
                },
                "tools": realtime_tools,
                "tool_choice": "auto"
            }
        }
        await openai_ws.send(json.dumps(session_update))

        # Variables d'àudio i identificació del client
        stream_sid = None
        telefon_client = "Desconegut"

        # --------------------------------------------------------
        # TASCA 1: Rebre àudio de TWILIO i enviar-lo a OPENAI
        # --------------------------------------------------------
        async def receive_from_twilio():
            nonlocal stream_sid, telefon_client
            try:
                async for message in twilio_ws.iter_text():
                    data = json.loads(message)
                    
                    if data['event'] == 'start':
                        stream_sid = data['start']['streamSid']
                        custom_params = data['start'].get('customParameters', {})
                        telefon_client = custom_params.get('telefon', 'Desconegut')
                        print(f"🔗 [TWILIO] Stream iniciat: {stream_sid} | Telèfon: {telefon_client}", flush=True)

                        # ENVIAR EL MISSATGE INICIAL DE BENVINGUDA
                        missatge_inicial = config_negoci.get("missatge_inicial")
                        if missatge_inicial:
                            init_event = {
                                "type": "response.create",
                                "response": {
                                    "instructions": f"Has de començar la trucada saludant ara mateix per iniciativa pròpia. Digues: '{missatge_inicial}'"
                                }
                            }
                            await openai_ws.send(json.dumps(init_event))
                        
                    elif data['event'] == 'media':
                        # Agafem l'àudio de Twilio i l'enviem directe a OpenAI
                        audio_event = {
                            "type": "input_audio_buffer.append",
                            "audio": data['media']['payload']
                        }
                        await openai_ws.send(json.dumps(audio_event))
                        
                    elif data['event'] == 'stop':
                        print("🛑 [TWILIO] La trucada ha finalitzat", flush=True)
                        break
            except Exception as e:
                print(f"❌ Error a Twilio -> OpenAI: {e}")

        # --------------------------------------------------------
        # TASCA 2: Rebre àudio i text d'OPENAI i enviar àudio a TWILIO
        # --------------------------------------------------------
        async def receive_from_openai():
            nonlocal stream_sid, telefon_client
            grace_task = None
            
            async def trigger_response_after_grace():
                """S'espera el temps (350ms) concedit com a Grace Window i a continuació dispara la resposta"""
                await asyncio.sleep(0.35) 
                try:
                    await openai_ws.send(json.dumps({"type": "response.create"}))
                except Exception as e:
                    print(f"❌ Error disparant resposta manual (grace window): {e}", flush=True)

            try:
                async for message in openai_ws:
                    response = json.loads(message)
                    event_type = response.get("type")

                    # === LÒGICA DE VAD AVANÇADA I BARGE-IN ===
                    if event_type == "input_audio_buffer.speech_started":
                        # L'usuari trunca el silenci -> L'INTERROMPI! 
                        if grace_task and not grace_task.done():
                            grace_task.cancel()
                        
                        # Aborta la reproducció emmagatzemada de Twilio a l'instant per a una veu fluida
                        if stream_sid:
                            try:
                                await twilio_ws.send_text(json.dumps({
                                    "event": "clear",
                                    "streamSid": stream_sid
                                }))
                                print("⚡ [BARGE-IN] S'atura l'àudio de sortida - El client intervé", flush=True)
                            except Exception:
                                pass
                                
                    elif event_type == "input_audio_buffer.speech_stopped":
                        # Inici del control personalitzat de la Grace Window (Silenci de la VAD fet)
                        grace_task = asyncio.create_task(trigger_response_after_grace())

                    # Si OpenAI ens envia un tros d'àudio amb la seva veu
                    elif event_type == "response.audio.delta" and response.get("delta"):
                        if stream_sid:
                            twilio_event = {
                                "event": "media",
                                "streamSid": stream_sid,
                                "media": {
                                    "payload": response["delta"]
                                }
                            }
                            await twilio_ws.send_text(json.dumps(twilio_event))

                    # Gestió de tools / reserves en temps real
                    elif event_type == "response.function_call_arguments.done":
                        call_id = response.get("call_id")
                        name = response.get("name")
                        arguments_raw = response.get("arguments")
                        
                        print(f"🔧 [TOOL CALL] Executant {name} amb args: {arguments_raw}", flush=True)
                        
                        # Injectar el telèfon del client als arguments de la tool
                        try:
                            args_dict = json.loads(arguments_raw)
                            args_dict["_telefon_client"] = telefon_client
                            arguments_enriched = json.dumps(args_dict)
                        except Exception:
                            arguments_enriched = arguments_raw
                        
                        resultat = await asyncio.to_thread(executar_tool, name, arguments_enriched, config_negoci, camps_requerits)
                        print(f"🔧 [TOOL RESULT] {resultat}", flush=True)
                        
                        tool_response_event = {
                            "type": "conversation.item.create",
                            "item": {
                                "type": "function_call_output",
                                "call_id": call_id,
                                "output": resultat
                            }
                        }
                        await openai_ws.send(json.dumps(tool_response_event))
                        await openai_ws.send(json.dumps({"type": "response.create"}))

                    # Per veure el que detecta a la consola (opcional, molt útil!)
                    elif event_type == "conversation.item.input_audio_transcription.completed":
                        print(f"👤 [USUARI]: {response.get('transcript')}", flush=True)
                    elif event_type == "response.audio_transcript.done":
                        print(f"🤖 [IA]: {response.get('transcript')}", flush=True)

            except Exception as e:
                print(f"❌ Error a OpenAI -> Twilio: {e}")

        # --------------------------------------------------------
        # Executar les dues direccions al mateix temps
        # --------------------------------------------------------
        await asyncio.gather(receive_from_twilio(), receive_from_openai())