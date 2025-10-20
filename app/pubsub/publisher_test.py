from google.cloud import pubsub_v1
from dotenv import load_dotenv
import os
import json
load_dotenv()

PROJECT_ID = os.getenv("PROJECT_ID") 
TOPIC_ID = os.getenv("TOPIC_ID")

publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path(PROJECT_ID, TOPIC_ID)

data = {
    "event": "credit_update",
    "data": {
        "email": "macamayar@gmail.com",
        "credits_change": -1
    }
}

data_bytes = json.dumps(data).encode("utf-8")

future = publisher.publish(topic_path, data_bytes)
print(f"✅ Mensaje publicado con ID: {future.result()}")
