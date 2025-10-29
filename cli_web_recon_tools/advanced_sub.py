import argparse
import requests
import aiohttp
import asyncio
import json
import dns.resolver
import re
from aiofiles import open as aio_open
from urllib.parse import urlparse
from art import text2art
ascii_art = text2art("tool", font="3d")

# Print the ASCII art
print(ascii_art)

class SubdomainEnumerator:
    def __init__(self, domain, wordlist=None, threads=20, output=None):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.output = output
        self.passive_subdomains = set()
        self.active_subdomains = set()
        self.session = None
        self.wildcard_ips = set()

    async def fetch_json(self, url):
        """Fetch JSON data from a given URL."""
        try:
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            print(f"Error fetching {url}: {e}")
        return None

    async def passive_enumeration(self):
        """Gather subdomains from passive sources without API keys."""
        sources = {
            "crt.sh": f"https://crt.sh/?q=%25.{self.domain}&output=json",
            "ThreatCrowd": f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}",
            "AlienVault": f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns",
            "RapidDNS": f"https://rapiddns.io/s/{self.domain}?full=1",
        }

        tasks = [self.fetch_json(url) for url in sources.values() if "rapiddns" not in url]
        responses = await asyncio.gather(*tasks)
        
        for i, (source, response) in enumerate(zip(sources.keys(), responses)):
            if response:
                if source == "crt.sh":
                    self.passive_subdomains.update(entry['name_value'].lower() for entry in response)
                elif source == "ThreatCrowd":
                    self.passive_subdomains.update(response.get("subdomains", []))
                elif source == "AlienVault":
                    self.passive_subdomains.update(entry["hostname"] for entry in response.get("passive_dns", []))

        # RapidDNS is HTML-based, so fetch it separately
        async with self.session.get(sources["RapidDNS"], timeout=10) as response:
            if response.status == 200:
                text = await response.text()
                self.passive_subdomains.update(re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', text))

    async def check_wildcard(self):
        """Detect if the domain has wildcard DNS."""
        try:
            test_subdomain = f"randomtest.{self.domain}"
            answers = dns.resolver.resolve(test_subdomain)
            self.wildcard_ips.update([str(ip) for ip in answers])
        except dns.resolver.NXDOMAIN:
            pass  # No wildcard detected
        except Exception:
            pass

    async def brute_force_subdomains(self):
        """Brute-force subdomains using asyncio and aiohttp."""
        if not self.wordlist:
            return
        
        async with aio_open(self.wordlist, 'r') as file:
            words = [line.strip() for line in await file.readlines()]
        
        queue = asyncio.Queue()
        for word in words:
            await queue.put(f"{word}.{self.domain}")
        
        async def worker():
            while not queue.empty():
                subdomain = await queue.get()
                try:
                    answers = dns.resolver.resolve(subdomain)
                    resolved_ips = [str(ip) for ip in answers]
                    if not self.wildcard_ips or not set(resolved_ips).issubset(self.wildcard_ips):
                        self.active_subdomains.add(subdomain)
                        print(f"[FOUND] {subdomain}")
                except dns.resolver.NXDOMAIN:
                    pass
                except Exception:
                    pass
        
        workers = [asyncio.create_task(worker()) for _ in range(self.threads)]
        await asyncio.gather(*workers)

    async def run(self):
        """Run passive and active enumeration."""
        async with aiohttp.ClientSession() as self.session:
            await self.passive_enumeration()
            await self.check_wildcard()
            await self.brute_force_subdomains()

        all_subdomains = sorted(self.passive_subdomains.union(self.active_subdomains))
        
        if self.output:
            async with aio_open(self.output, "w") as f:
                await f.writelines(f"{sub}\n" for sub in all_subdomains)
            print(f"Results saved to {self.output}")

        print("\n[Final Results]")
        for sub in all_subdomains:
            print(sub)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Efficient Subdomain Enumeration Tool")
    parser.add_argument("domain", help="Target domain to enumerate subdomains for.")
    parser.add_argument("-w", "--wordlist", help="Path to a wordlist for brute-force enumeration.")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads for brute-force (default: 20)")
    parser.add_argument("-o", "--output", help="Output file to save results.")
    
    args = parser.parse_args()
    
    enumerator = SubdomainEnumerator(args.domain, args.wordlist, args.threads, args.output)
    asyncio.run(enumerator.run())
