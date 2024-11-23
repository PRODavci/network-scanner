import ipaddress
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor

import nmap3


def get_max_workers():
    """
    Возвращает максимальное количество потоков, исходя из доступных ядер процессора.
    """
    try:
        return os.cpu_count() or 1
    except Exception:
        return 1


class NetworkScanner(object):
    @staticmethod
    def is_host_address(s: str):
        """Проверяет, является ли строка IP-адресом."""
        return bool(re.fullmatch(r'^[\d.]+$', s))

    @staticmethod
    def is_domain_name(s: str):
        return bool(re.fullmatch(r'^(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$', s))

    def clear_not_hosts(self, data: dict):
        """Удаляет из результата все ключи, которые не являются IP-адресами."""
        return {key: value for key, value in data.items() if self.is_host_address(key)}

    @staticmethod
    def no_port_scan(targets: list):
        nmap = nmap3.NmapHostDiscovery()
        targets = ' '.join(targets)
        results = nmap.nmap_no_portscan(f"{targets}")
        return results

    def get_alive_hosts(self, targets: list):
        results = self.clear_not_hosts(self.no_port_scan(targets))
        result = []
        for host in results:
            if results[host]['state']['state'] == 'up':
                result.append(host)
        return result

    @staticmethod
    def chunkify(targets, batch_size=10):
        """
        Разделяет список целей на батчи.
        """
        for i in range(0, len(targets), batch_size):
            yield targets[i:i + batch_size]

    def get_alive_hosts_multithreaded(self, targets: list, batch_size: int = 10, max_workers=None):
        """
        Выполняет поиск активных хостов в многопоточном режиме.
        """
        if max_workers is None:
            max_workers = get_max_workers()
        target_batches = list(self.chunkify(targets, batch_size))
        alive_hosts = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.get_alive_hosts, batch) for batch in target_batches]
            for future in futures:
                try:
                    alive_hosts.extend(future.result())
                except Exception as e:
                    print(f"Error while processing batch: {e}")

        return alive_hosts

    def get_service_version(self, target: str):
        nmap = nmap3.Nmap()
        nmap_discovery = nmap3.NmapHostDiscovery()
        quick_scan = nmap_discovery.nmap_portscan_only(target, args="-T4 -p- --open")

        open_ports = [
            port_info["portid"] for port_info in quick_scan.get(target, {}).get("ports", [])
        ]
        detailed_args = f"-sS -sU -p {','.join(open_ports)}" if open_ports else "-p-"

        detailed_scan = nmap.nmap_version_detection(f"{target}", args=detailed_args)

        return self.format_service_version(detailed_scan)

    def get_service_versions_multithreaded(self, targets, action=None, max_workers=None,):
        """
        Выполняет многопоточное получение информации о версиях сервисов для нескольких хостов.
        """
        if max_workers is None:
            max_workers = get_max_workers()

        results = {}

        def worker(target):
            start_time = time.time()
            try:
                results[target] = self.get_service_version(target)
                elapsed_time = time.time() - start_time
                print(f"Time taken for {target}: {elapsed_time:.2f} seconds")

                if action is not None:
                    action(target, results[target])

            except Exception as e:
                print(f"Error processing {target}: {e}")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(worker, targets)

        return results

    def format_service_version(self, service):
        transformed_data = {}

        for ip, data in self.clear_not_hosts(service).items():
            services = []
            for port_info in data.get('ports', []):
                service_details = {
                    "port": port_info.get("portid"),
                    "protocol": port_info.get("protocol"),
                    "name": port_info.get("service", {}).get("name"),
                    "product": port_info.get("service", {}).get("product"),
                    "version": port_info.get("service", {}).get("version"),
                    "ostype": port_info.get("service", {}).get("ostype"),
                    "conf": port_info.get("service", {}).get("conf"),
                    "cpe": [entry.get("cpe") for entry in port_info.get("cpe", [])],
                }
                services.append(service_details)

            transformed_data[ip] = {"services": services}

        return transformed_data

    def parse_targets(self, target: str, spliter=','):
        targets = []
        if spliter in target:
            for item in target.split(spliter):
                targets.extend(self.parse_targets(item.strip()))

        elif "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            targets = [str(ip) for ip in network.hosts()]

        elif "-" in target:
            start_ip, end_ip = target.split("-")
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            current = start
            while current <= end:
                targets.append(str(current))
                current += 1
        elif self.is_domain_name(target):
            targets = [target]
        else:
            ipaddress.ip_address(target)
            targets = [target]

        return list(set(targets))
