from typing import Any

import pika
import json

from dotenv import load_dotenv

from config import config

load_dotenv()

RABBIT_HOST = config.RABBITMQ_HOST
RABBIT_PORT = config.RABBITMQ_PORT
RABBITMQ_USER = config.RABBITMQ_USER
RABBITMQ_PASSWORD = config.RABBITMQ_PASSWORD

credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASSWORD)
parameters = pika.ConnectionParameters(RABBIT_HOST, RABBIT_PORT, '/', credentials)


def send_to_queue(data: Any):
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    channel.queue_declare(
        queue='backend-api'
    )
    data = json.dumps(data)
    channel.basic_publish(
        exchange='',
        routing_key='backend-api',
        body=data.encode(),
    )
    connection.close()
    print(" [x] Data published successfully!")