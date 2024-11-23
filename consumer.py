import json
import threading

import pika
from dotenv import load_dotenv

import publisher
from config import config
from scanner import NetworkScanner

load_dotenv()

RABBIT_HOST = config.RABBITMQ_HOST
RABBIT_PORT = config.RABBITMQ_PORT
RABBITMQ_USER = config.RABBITMQ_USER
RABBITMQ_PASSWORD = config.RABBITMQ_PASSWORD

BACKEND_QUEUE = 'backend-api'

credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASSWORD)
parameters = pika.ConnectionParameters(RABBIT_HOST, RABBIT_PORT, '/', credentials)

connection = pika.BlockingConnection(parameters)
channel = connection.channel()
channel.queue_declare(queue='network-scanner')
channel.basic_qos(prefetch_count=1)


def start_scan(data: dict):
    # network_str_example = "192.168.178.3,192.168.178.4,192.168.178.5-192.168.178.7,192.168.178.0/29"
    global is_scanning

    network = data['network']
    scanner = NetworkScanner()

    targets = scanner.parse_targets(network)
    print(targets)

    result = scanner.get_alive_hosts_multithreaded(targets)
    data = {
        'type': 'alive_hosts',
        'data': result,
    }
    print(data)
    publisher.send_to_queue(data)

    def on_get_action(target, services):
        data = {
            'type': 'host_service',
            'data': {
                'host': target,
                'services': services,
            }
        }
        print(data)
        publisher.send_to_queue(data)

    scanner.get_service_versions_multithreaded(result, action=on_get_action)
    is_scanning = False
    print("Scanning finished")


def callback(ch, method, properties, body):
    global threads, is_scanning
    data = json.loads(body)
    print(" [x] Received dictionary:", data, is_scanning)

    if data['type'] == 'start_scan' and not is_scanning:
        print("Starting scan")
        t = threading.Thread(target=start_scan, args=(data, ))
        is_scanning = True
        t.start()
        threads.append(t)

    else:
        print("Scanning already started")

    ch.basic_ack(delivery_tag=method.delivery_tag)


threads = []
is_scanning = False
channel.basic_consume(queue='network-scanner', on_message_callback=callback, auto_ack=False)

print(' [*] Waiting for messages. To exit press CTRL+C')
channel.start_consuming()

for thread in threads:
    thread.join()
