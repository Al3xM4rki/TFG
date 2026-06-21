import logging
import asyncio
import requests
from telethon import TelegramClient, events
from datetime import datetime

api_id = 000       
api_hash = 'xxxxxxxxxxxx' 
IDS = [-000, -000, -000]
WEBHOOK = "https://aaaa/webhook/xxxxx-xxxxxx-xxxxxx"

logging.basicConfig(level=logging.INFO)

client = TelegramClient('sesion', api_id, api_hash)

@client.on(events.NewMessage(chats=IDS))
async def handler(event):
    
    print(f" Mensaje recibido de ID: {event.chat_id}")
    
    try:
        chat = await event.get_chat()
        # Si tiene título (canal/grupo) se usa. Si no, ID.
        channel_name = getattr(chat, 'title', str(event.chat_id))
    except Exception as e:
        logging.warning(f"No se pudo obtener el nombre del canal: {e}")
        channel_name = str(event.chat_id)

    message = event.raw_text
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if message:
        datos = {
            "message": message,
            "channel": channel_name,
            "date": now
        }

        try:
            response = requests.post(WEBHOOK, json=datos)
            logging.info(f"Mensaje recibido desde: {channel_name} y enviado al webhook con respuesta: {response.status_code}")
        except Exception as e:
            logging.error(f"Error al enviar mensaje al webhook: {e}")
                

print("Escuchando todos los chats")
client.start()
client.run_until_disconnected()