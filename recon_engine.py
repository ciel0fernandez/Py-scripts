#!/usr/bin/env python3

import asyncio
import aiohttp
import socket
import argparse
import sys
from typing import Set, Dict, Any, List

class ReconEngine:
    def __init__(self, target: str, timeout: int = 5, concurrency: int = 50):
        self.target = target.strip().lower()
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.semaphore = asyncio.Semaphore(concurrency)
        self.discovered_domains: Set[str] = set()
        self.live_assets: List[Dict[str, Any]] = []

    async def fetch_crt_sh(self, session: aiohttp.ClientSession) -> Set[str]:
        """Passive enumeration using Certificate Transparency logs via crt.sh."""
        url = f"https://crt.sh/?q=%.{self.target}&output=json"
        domains = set()
        try:
            async with session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    for entry in data:
                        raw_sub = entry.get("name_value", "")
                        for sub in raw_sub.split("\n"):
                            sub = sub.strip().lower()
                            if not sub.startswith("*.") and sub.endswith(self.target):
                                domains.add(sub)
        except Exception as e:
            print(f"[-] CRT.sh query failed: {e}", file=sys.stderr)
        return domains

    async def resolve_dns(self, hostname: str) -> str | None:
        """Asynchronously resolve hostname to IPv4."""
        loop = asyncio.get_running_loop()
        try:
            addr_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            return addr_info[0][4][0]
        except (socket.gaierror, IndexError):
            return None

    async def probe_endpoint(self, session: aiohttp.ClientSession, hostname: str, ip: str):
        """Probe HTTP/HTTPS endpoints and collect tech metadata."""
        async with self.semaphore:
            protocols = ["https://", "http://"]
            for proto in protocols:
                target_url = f"{proto}{hostname}"
                try:
                    async with session.get(
                        target_url, 
                        timeout=self.timeout, 
                        allow_redirects=True, 
                        ssl=False
                    ) as resp:
                        server = resp.headers.get("Server", "Unknown")
                        self.live_assets.append({
                            "host": hostname,
                            "ip": ip,
                            "url": str(resp.url),
                            "status": resp.status,
                            "server": server
                        })
                        print(f"[+] [{resp.status}] {target_url} -> IP: {ip} | Server: {server}")
                        break
                except Exception:
                    continue

    async def run(self):
        print(f"[*] Initiating passive reconnaissance for: {self.target}")
        
        async with aiohttp.ClientSession() as session:
            # Step 1: Passive OSINT Subdomain Enumeration
            self.discovered_domains = await self.fetch_crt_sh(session)
            self.discovered_domains.add(self.target)
            print(f"[+] Found {len(self.discovered_domains)} potential targets.")

            # Step 2: Concurrency-limited DNS + HTTP Probing
            print("[*] Probing hosts and resolving infrastructure...")
            tasks = []
            for sub in self.discovered_domains:
                tasks.append(self._process_host(session, sub))
            
            await asyncio.gather(*tasks)

        print(f"\n[✓] Reconnaissance complete. {len(self.live_assets)} live web assets identified.")

    async def _process_host(self, session: aiohttp.ClientSession, host: str):
        ip = await self.resolve_dns(host)
        if ip:
            await self.probe_endpoint(session, host, ip)


def main():
    parser = argparse.ArgumentParser(description="Async Target Reconnaissance & Probing Engine")
    parser.add_argument("-d", "--domain", required=True, help="Target root domain (e.g., example.com)")
    parser.add_argument("-c", "--concurrency", type=int, default=30, help="Concurrency limit (default: 30)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    args = parser.parse_args()

    engine = ReconEngine(target=args.domain, timeout=args.timeout, concurrency=args.concurrency)
    asyncio.run(engine.run())


if __name__ == "__main__":
    main()
