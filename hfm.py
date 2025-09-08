#!/usr/bin/env python3
"""
Hetzner Robot Firewall Manager
Complete solution for managing Hetzner server firewalls via Robot API
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# Load environment variables
load_dotenv()


class HetznerFirewallManager:
    """Manage Hetzner Robot Firewall configurations"""
    
    def __init__(self, config_file: str = "firewall_config.json"):
        self.config_file = Path(config_file)
        self.base_url = "https://robot-ws.your-server.de"
        
        # Get credentials from environment
        self.username = os.getenv('HETZNER_USER')
        self.password = os.getenv('HETZNER_PASS')
        
        if not self.username or not self.password:
            raise ValueError("Please set HETZNER_USER and HETZNER_PASS in .env file")
        
        # Setup session
        self.auth = HTTPBasicAuth(self.username, self.password)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Load or create config
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Load configuration from file"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                return json.load(f)
        return {"profiles": {}}
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def get_current_public_ip(self) -> Optional[str]:
        """Get the current public IP address"""
        services = [
            "https://ipinfo.io/ip",
            "https://ifconfig.me",
            "https://api.ipify.org",
            "https://icanhazip.com"
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    return ip
            except Exception:
                continue
        
        return None
    
    def get_all_servers(self) -> List[Dict]:
        """Get all servers from Hetzner API"""
        try:
            response = self.session.get(f"{self.base_url}/server")
            response.raise_for_status()
            data = response.json()
            
            # Extract servers from the response
            servers = []
            for item in data:
                if isinstance(item, dict) and 'server' in item:
                    servers.append(item['server'])
            
            return servers
        except requests.exceptions.RequestException as e:
            print(f"Failed to get servers: {e}", file=sys.stderr)
            return []
    
    def get_firewall(self, server_ip: str) -> Optional[Dict]:
        """Get current firewall configuration for a server"""
        try:
            response = self.session.get(f"{self.base_url}/firewall/{server_ip}")
            
            if response.status_code == 404:
                return None
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get firewall for {server_ip}: {e}", file=sys.stderr)
            return None
    
    def update_firewall(self, server_ip: str, rules: Dict[str, Any]) -> bool:
        """Update firewall configuration for a server with retry logic for FIREWALL_IN_PROCESS"""
        # Build form data (URL-encoded format)
        data = {
            'filter_ipv6': str(rules.get('filter_ipv6', False)).lower(),
            'whitelist_hos': str(rules.get('whitelist_hos', True)).lower(),
        }
        
        # Encode input rules
        for i, rule in enumerate(rules.get('input', [])):
            for key, value in rule.items():
                if value is None:
                    continue
                form_key = f'rules[input][{i}][{key}]'
                if isinstance(value, bool):
                    data[form_key] = str(value).lower()
                else:
                    data[form_key] = str(value)
        
        # Encode output rules
        for i, rule in enumerate(rules.get('output', [])):
            for key, value in rule.items():
                if value is None:
                    continue
                form_key = f'rules[output][{i}][{key}]'
                if isinstance(value, bool):
                    data[form_key] = str(value).lower()
                else:
                    data[form_key] = str(value)
        
        # Retry logic with exponential backoff
        max_retries = 6  # Total wait time: ~63 seconds (1+2+4+8+16+32)
        retry_delay = 1
        
        for attempt in range(max_retries + 1):
            try:
                response = self.session.post(
                    f"{self.base_url}/firewall/{server_ip}",
                    data=data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                
                if response.status_code in [200, 202]:
                    return True
                elif response.status_code == 409:
                    # Check if it's a FIREWALL_IN_PROCESS error
                    try:
                        error_data = response.json()
                        if error_data.get('error', {}).get('code') == 'FIREWALL_IN_PROCESS':
                            if attempt < max_retries:
                                print(f"  Firewall update in progress, waiting {retry_delay}s before retry (attempt {attempt + 1}/{max_retries})...")
                                time.sleep(retry_delay)
                                retry_delay *= 2  # Exponential backoff
                                continue
                            else:
                                print(f"  Firewall still busy after {max_retries} retries")
                                return False
                    except:
                        pass
                    
                    print(f"Failed with status {response.status_code}: {response.text[:200]}")
                    return False
                else:
                    print(f"Failed with status {response.status_code}: {response.text[:200]}")
                    return False
            except Exception as e:
                print(f"Error updating firewall: {e}")
                return False
        
        return False
    
    def add_ip_to_server(self, server_ip: str, ip_to_add: str, comment: str = "") -> bool:
        """Add an IP to a server's firewall"""
        # Get current firewall
        firewall_response = self.get_firewall(server_ip)
        if not firewall_response or 'firewall' not in firewall_response:
            print(f"  WARNING: No firewall configured on server {server_ip}")
            return False
        
        current_firewall = firewall_response['firewall']
        current_rules = current_firewall.get('rules', {"input": [], "output": []})
        
        # Normalize IP format
        if '/' not in ip_to_add:
            ip_to_add = f"{ip_to_add}/32"
        
        # Check if IP already exists
        for rule in current_rules['input']:
            if rule.get('src_ip') and ip_to_add in rule['src_ip']:
                print(f"  INFO: IP {ip_to_add} already exists")
                return True
        
        # Add new rule
        new_rule = {
            "ip_version": "ipv4",
            "name": comment[:50] if comment else f"Allow {ip_to_add}",
            "dst_ip": None,
            "src_ip": ip_to_add,
            "dst_port": None,
            "src_port": None,
            "protocol": "tcp",
            "tcp_flags": None,
            "action": "accept"
        }
        
        # Insert at beginning
        current_rules['input'].insert(0, new_rule)
        
        # Update firewall - keep output rules EXACTLY as they are
        update_data = {
            'filter_ipv6': current_firewall.get('filter_ipv6', False),
            'whitelist_hos': current_firewall.get('whitelist_hos', True),
            'input': current_rules['input'],
            'output': current_rules['output']  # Don't modify output rules at all
        }
        
        if self.update_firewall(server_ip, update_data):
            print(f"  SUCCESS: Added {ip_to_add}")
            return True
        else:
            print(f"  FAILED: Failed to add {ip_to_add}")
            return False
    
    def remove_ip_from_server(self, server_ip: str, ip_to_remove: str) -> bool:
        """Remove an IP from a server's firewall"""
        # Get current firewall
        firewall_response = self.get_firewall(server_ip)
        if not firewall_response or 'firewall' not in firewall_response:
            print(f"  WARNING: No firewall configured on server {server_ip}")
            return False
        
        current_firewall = firewall_response['firewall']
        current_rules = current_firewall.get('rules', {"input": [], "output": []})
        
        # Normalize IP format
        if '/' not in ip_to_remove:
            ip_to_remove = f"{ip_to_remove}/32"
        
        # Find and remove the IP
        original_count = len(current_rules['input'])
        current_rules['input'] = [
            rule for rule in current_rules['input']
            if not (rule.get('src_ip') and ip_to_remove in rule['src_ip'])
        ]
        
        if len(current_rules['input']) == original_count:
            print(f"  WARNING: IP {ip_to_remove} not found")
            return False
        
        # Update firewall - keep output rules EXACTLY as they are
        update_data = {
            'filter_ipv6': current_firewall.get('filter_ipv6', False),
            'whitelist_hos': current_firewall.get('whitelist_hos', True),
            'input': current_rules['input'],
            'output': current_rules['output']  # Don't modify output rules at all
        }
        
        if self.update_firewall(server_ip, update_data):
            print(f"  SUCCESS: Removed {ip_to_remove}")
            return True
        else:
            print(f"  FAILED: Failed to remove {ip_to_remove}")
            return False
    
    def verify_ip_on_server(self, server_ip: str, ip_to_check: str) -> bool:
        """Verify if an IP is whitelisted on a server"""
        firewall_response = self.get_firewall(server_ip)
        if not firewall_response or 'firewall' not in firewall_response:
            return False
        
        firewall = firewall_response['firewall']
        rules = firewall.get('rules', {})
        input_rules = rules.get('input', [])
        
        # Normalize IP for comparison
        if '/' not in ip_to_check:
            ip_to_check_with_mask = f"{ip_to_check}/32"
        else:
            ip_to_check_with_mask = ip_to_check
        
        # Check if IP is in any rule
        for rule in input_rules:
            if rule.get('action') == 'accept' and rule.get('src_ip'):
                src_ip = rule['src_ip']
                if ip_to_check in src_ip or ip_to_check_with_mask == src_ip:
                    return True
        
        return False
    
    def bootstrap_from_api(self) -> int:
        """Import existing firewall configurations from Hetzner API"""
        print("Fetching servers from Hetzner API...")
        servers = self.get_all_servers()
        
        if not servers:
            print("No servers found")
            return 0
        
        print(f"Found {len(servers)} server(s)")
        imported_count = 0
        
        for server in servers:
            server_ip = server.get('server_ip')
            server_name = server.get('server_name', '')
            server_number = server.get('server_number')
            
            if not server_ip:
                continue
            
            print(f"\nServer: {server_name or server_number} ({server_ip})")
            
            # Get firewall configuration
            firewall_response = self.get_firewall(server_ip)
            if not firewall_response or 'firewall' not in firewall_response:
                print("  ⚠ No firewall configured")
                continue
            
            firewall = firewall_response['firewall']
            
            # Create profile name
            if server_name:
                profile_name = server_name.lower().replace(' ', '-').replace('.', '-')
            else:
                profile_name = f"server-{server_number}"
            
            # Make sure profile name is unique
            base_name = profile_name
            counter = 1
            while profile_name in self.config.get("profiles", {}):
                profile_name = f"{base_name}-{counter}"
                counter += 1
            
            # Extract whitelisted IPs
            permanent_whitelist = []
            rules = firewall.get('rules', {})
            input_rules = rules.get('input', [])
            
            for rule in input_rules:
                if rule.get('action') == 'accept' and rule.get('src_ip'):
                    src_ip = rule.get('src_ip')
                    rule_name = rule.get('name', '')
                    dst_port = rule.get('dst_port')
                    
                    # Check if this IP already exists in whitelist
                    existing_entry = None
                    for entry in permanent_whitelist:
                        if entry['ip'] == src_ip:
                            existing_entry = entry
                            break
                    
                    if existing_entry:
                        if dst_port and dst_port not in existing_entry['ports']:
                            existing_entry['ports'].append(dst_port)
                    else:
                        entry = {
                            'ip': src_ip,
                            'ports': [dst_port] if dst_port else [],
                            'comment': rule_name[:50] if rule_name else ''
                        }
                        permanent_whitelist.append(entry)
            
            # Create profile configuration
            profile_config = {
                'server_ip': server_ip,
                'server_name': server_name or f"Server {server_number}",
                'permanent_whitelist': permanent_whitelist,
                'filter_ipv6': firewall.get('filter_ipv6', False),
                'whitelist_hos': firewall.get('whitelist_hos', True)
            }
            
            # Add profile to configuration
            self.config.setdefault("profiles", {})[profile_name] = profile_config
            
            print(f"  Imported as profile '{profile_name}'")
            print(f"    - {len(permanent_whitelist)} whitelisted IPs")
            imported_count += 1
        
        # Save configuration
        self.save_config()
        print(f"\nImported {imported_count} server configuration(s)")
        return imported_count
    
    def whitelist_current_ip(self, comment: str = "Current location", verify: bool = False) -> int:
        """Add current public IP to all servers"""
        # Get current IP
        print("Getting current public IP...")
        current_ip = self.get_current_public_ip()
        
        if not current_ip:
            print("Failed to determine current public IP!")
            return 0
        
        print(f"Current public IP: {current_ip}\n")
        
        profiles = self.config.get("profiles", {})
        if not profiles:
            print("No profiles found. Run 'bootstrap' first.")
            return 0
        
        print(f"Found {len(profiles)} profile(s): {', '.join(profiles.keys())}")
        print("\n" + "=" * 60)
        print("Adding IP to all servers...")
        print("=" * 60 + "\n")
        
        success_count = 0
        
        for profile_name, profile_config in profiles.items():
            server_ip = profile_config.get("server_ip")
            server_name = profile_config.get("server_name", "")
            
            if not server_ip:
                print(f"\n⚠ Profile '{profile_name}' has no server IP")
                continue
            
            print(f"\nProfile: {profile_name}")
            print(f"Server: {server_name} ({server_ip})")
            
            if self.add_ip_to_server(server_ip, current_ip, comment):
                success_count += 1
                
                # Update local config
                ip_entry = {
                    "ip": f"{current_ip}/32" if '/' not in current_ip else current_ip,
                    "ports": [],
                    "comment": comment
                }
                
                # Check if IP already in config
                already_in_config = False
                for entry in profile_config.get("permanent_whitelist", []):
                    if isinstance(entry, dict) and current_ip in entry.get("ip", ""):
                        already_in_config = True
                        break
                
                if not already_in_config:
                    profile_config.setdefault("permanent_whitelist", []).append(ip_entry)
                
                # Verify if requested
                if verify:
                    print("  Waiting 5 seconds before verification...")
                    time.sleep(5)
                    if self.verify_ip_on_server(server_ip, current_ip):
                        print(f"  VERIFIED: {current_ip} is whitelisted")
                    else:
                        print(f"  NOT VERIFIED: {current_ip} may not be applied yet")
        
        # Save updated config
        self.save_config()
        
        # Summary
        print("\n" + "=" * 60)
        print("Summary")
        print("=" * 60)
        print(f"\nSuccessfully updated {success_count}/{len(profiles)} server(s)")
        
        return success_count
    
    def remove_current_ip(self, verify: bool = False) -> int:
        """Remove current public IP from all servers"""
        print("Getting current public IP...")
        current_ip = self.get_current_public_ip()
        
        if not current_ip:
            print("Failed to get current public IP")
            return 0
        
        print(f"Current public IP: {current_ip}")
        
        profiles = self.config.get("profiles", {})
        if not profiles:
            print("No profiles configured. Run 'bootstrap' to import from API.")
            return 0
        
        print(f"\nFound {len(profiles)} profile(s): {', '.join(profiles.keys())}")
        
        print("\n" + "=" * 60)
        print("Removing IP from all servers...")
        print("=" * 60)
        print()
        
        success_count = 0
        for profile_name, profile_config in profiles.items():
            server_ip = profile_config.get("server_ip")
            server_name = profile_config.get("server_name", "")
            
            if not server_ip:
                print(f"\nWARNING: Profile '{profile_name}' has no server IP")
                continue
            
            print(f"\nProfile: {profile_name}")
            print(f"Server: {server_name} ({server_ip})")
            
            if self.remove_ip_from_server(server_ip, current_ip):
                success_count += 1
                
                # Update local config - remove from permanent_whitelist
                whitelist = profile_config.get("permanent_whitelist", [])
                updated_whitelist = []
                for entry in whitelist:
                    if isinstance(entry, dict):
                        entry_ip = entry.get("ip", "")
                        if current_ip not in entry_ip:
                            updated_whitelist.append(entry)
                    else:
                        # Handle string entries
                        if current_ip not in str(entry):
                            updated_whitelist.append(entry)
                
                profile_config["permanent_whitelist"] = updated_whitelist
                
                # Verify if requested
                if verify:
                    print("  Waiting 5 seconds before verification...")
                    time.sleep(5)
                    if not self.verify_ip_on_server(server_ip, current_ip):
                        print(f"  VERIFIED: {current_ip} has been removed")
                    else:
                        print(f"  NOT VERIFIED: {current_ip} may still be present")
        
        # Save updated config
        self.save_config()
        
        # Summary
        print("\n" + "=" * 60)
        print("Summary")
        print("=" * 60)
        print(f"\nSuccessfully removed IP from {success_count}/{len(profiles)} server(s)")
        
        return success_count
    
    def list_profiles(self):
        """List all configured profiles"""
        profiles = self.config.get("profiles", {})
        
        if not profiles:
            print("No profiles configured. Run 'bootstrap' to import from API.")
            return
        
        print("\nConfigured Profiles:")
        print("-" * 60)
        
        for profile_name, profile_config in profiles.items():
            server_ip = profile_config.get("server_ip", "Not configured")
            server_name = profile_config.get("server_name", "")
            whitelist_count = len(profile_config.get("permanent_whitelist", []))
            
            print(f"\nProfile: {profile_name}")
            print(f"  Server: {server_name} ({server_ip})")
            print(f"  Whitelisted IPs: {whitelist_count}")
    
    def list_ips(self, profile: Optional[str] = None, from_api: bool = True):
        """List whitelisted IPs for a profile or all profiles"""
        profiles = self.config.get("profiles", {})
        
        if profile:
            if profile not in profiles:
                print(f"Profile '{profile}' not found")
                return
            profiles_to_show = {profile: profiles[profile]}
        else:
            profiles_to_show = profiles
        
        for profile_name, profile_config in profiles_to_show.items():
            server_ip = profile_config.get("server_ip")
            server_name = profile_config.get("server_name", "")
            
            print(f"\nProfile: {profile_name}")
            print(f"Server: {server_name} ({server_ip})")
            print("-" * 40)
            
            if not server_ip:
                print("  ⚠ No server IP configured")
                continue
            
            if from_api:
                # Get current rules from API
                print("  Fetching from API...")
                firewall_response = self.get_firewall(server_ip)
                
                if not firewall_response or 'firewall' not in firewall_response:
                    print("  ⚠ No firewall configured on server")
                    continue
                
                firewall = firewall_response['firewall']
                rules = firewall.get('rules', {})
                input_rules = rules.get('input', [])
                
                # Group IPs and their rules
                ip_rules = {}
                for rule in input_rules:
                    if rule.get('action') == 'accept' and rule.get('src_ip'):
                        src_ip = rule.get('src_ip')
                        rule_name = rule.get('name', '')
                        dst_port = rule.get('dst_port')
                        
                        if src_ip not in ip_rules:
                            ip_rules[src_ip] = {
                                'names': [],
                                'ports': []
                            }
                        
                        if rule_name and rule_name not in ip_rules[src_ip]['names']:
                            ip_rules[src_ip]['names'].append(rule_name)
                        
                        if dst_port and dst_port not in ip_rules[src_ip]['ports']:
                            ip_rules[src_ip]['ports'].append(dst_port)
                
                if not ip_rules:
                    print("  No whitelisted IPs found")
                else:
                    print(f"  Found {len(ip_rules)} whitelisted IP(s):\n")
                    for ip, info in sorted(ip_rules.items()):
                        # Build description
                        if info['ports']:
                            port_str = f" (ports: {', '.join(info['ports'])})"
                        else:
                            port_str = " (all TCP)"
                        
                        if info['names']:
                            # Use the first meaningful name
                            name = next((n for n in info['names'] if n and not n.startswith('Allow')), info['names'][0])
                            print(f"  - {ip}{port_str} - {name}")
                        else:
                            print(f"  - {ip}{port_str}")
                
                # Also show rules that allow specific ports from any IP
                port_rules = []
                for rule in input_rules:
                    if rule.get('action') == 'accept' and not rule.get('src_ip') and rule.get('dst_port'):
                        port_rules.append(rule)
                
                if port_rules:
                    print(f"\n  Open ports (any IP):")
                    for rule in port_rules:
                        port = rule.get('dst_port', '')
                        name = rule.get('name', '')
                        if name:
                            print(f"  - Port {port} - {name}")
                        else:
                            print(f"  - Port {port}")
            else:
                # Use local config (old behavior)
                whitelist = profile_config.get("permanent_whitelist", [])
                if not whitelist:
                    print("  No whitelisted IPs in local config")
                    continue
                
                for entry in whitelist:
                    if isinstance(entry, dict):
                        ip = entry.get("ip", "")
                        comment = entry.get("comment", "")
                        ports = entry.get("ports", [])
                        
                        if ports:
                            port_str = f" (ports: {', '.join(map(str, ports))})"
                        else:
                            port_str = " (all TCP)"
                        
                        if comment:
                            print(f"  • {ip}{port_str} - {comment}")
                        else:
                            print(f"  - {ip}{port_str}")
                    else:
                        print(f"  - {entry}")


def main():
    parser = argparse.ArgumentParser(
        description="Hetzner Robot Firewall Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s bootstrap                    # Import existing configurations from API
  %(prog)s whitelist-current            # Add current IP to all servers
  %(prog)s add 1.2.3.4 --comment "Office"  # Add specific IP to all servers
  %(prog)s remove 1.2.3.4               # Remove IP from all servers
  %(prog)s list                         # List all profiles
  %(prog)s list-ips                    # List all whitelisted IPs
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Bootstrap command
    subparsers.add_parser('bootstrap', help='Import existing firewall configurations from API')
    
    # Whitelist current IP
    whitelist_parser = subparsers.add_parser('whitelist-current', help='Add current public IP to all servers')
    whitelist_parser.add_argument('--comment', '-c', default='Current location', help='Comment for the IP')
    whitelist_parser.add_argument('--verify', '-v', action='store_true', help='Verify after adding')
    
    # Remove current IP
    remove_current_parser = subparsers.add_parser('remove-current', help='Remove current public IP from all servers')
    remove_current_parser.add_argument('--verify', '-v', action='store_true', help='Verify after removing')
    
    # Add IP
    add_parser = subparsers.add_parser('add', help='Add an IP to all servers')
    add_parser.add_argument('ip', help='IP address to add')
    add_parser.add_argument('--comment', '-c', default='', help='Comment for the IP')
    add_parser.add_argument('--profile', '-p', help='Specific profile (default: all)')
    
    # Remove IP
    remove_parser = subparsers.add_parser('remove', help='Remove an IP from all servers')
    remove_parser.add_argument('ip', help='IP address to remove')
    remove_parser.add_argument('--profile', '-p', help='Specific profile (default: all)')
    
    # List profiles
    subparsers.add_parser('list', help='List all configured profiles')
    
    # List IPs
    list_ips_parser = subparsers.add_parser('list-ips', help='List whitelisted IPs from API')
    list_ips_parser.add_argument('--profile', '-p', help='Specific profile (default: all)')
    list_ips_parser.add_argument('--local', action='store_true', help='Use local config instead of API')
    
    # Verify IP
    verify_parser = subparsers.add_parser('verify', help='Verify if an IP is whitelisted')
    verify_parser.add_argument('ip', help='IP address to verify')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        manager = HetznerFirewallManager()
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Execute commands
    if args.command == 'bootstrap':
        manager.bootstrap_from_api()
    
    elif args.command == 'whitelist-current':
        manager.whitelist_current_ip(args.comment, args.verify)
    
    elif args.command == 'remove-current':
        manager.remove_current_ip(args.verify)
    
    elif args.command == 'add':
        profiles = manager.config.get("profiles", {})
        if args.profile:
            if args.profile not in profiles:
                print(f"Profile '{args.profile}' not found")
                return
            profiles_to_update = {args.profile: profiles[args.profile]}
        else:
            profiles_to_update = profiles
        
        success_count = 0
        for profile_name, profile_config in profiles_to_update.items():
            server_ip = profile_config.get("server_ip")
            if server_ip:
                print(f"\nProfile: {profile_name}")
                if manager.add_ip_to_server(server_ip, args.ip, args.comment):
                    success_count += 1
        
        print(f"\nAdded IP to {success_count}/{len(profiles_to_update)} server(s)")
    
    elif args.command == 'remove':
        profiles = manager.config.get("profiles", {})
        if args.profile:
            if args.profile not in profiles:
                print(f"Profile '{args.profile}' not found")
                return
            profiles_to_update = {args.profile: profiles[args.profile]}
        else:
            profiles_to_update = profiles
        
        success_count = 0
        for profile_name, profile_config in profiles_to_update.items():
            server_ip = profile_config.get("server_ip")
            if server_ip:
                print(f"\nProfile: {profile_name}")
                if manager.remove_ip_from_server(server_ip, args.ip):
                    success_count += 1
        
        print(f"\nRemoved IP from {success_count}/{len(profiles_to_update)} server(s)")
    
    elif args.command == 'list':
        manager.list_profiles()
    
    elif args.command == 'list-ips':
        manager.list_ips(args.profile, from_api=not args.local)
    
    elif args.command == 'verify':
        profiles = manager.config.get("profiles", {})
        print(f"\nVerifying IP {args.ip} on all servers...")
        print("-" * 60)
        
        for profile_name, profile_config in profiles.items():
            server_ip = profile_config.get("server_ip")
            if server_ip:
                status = "[WHITELISTED]" if manager.verify_ip_on_server(server_ip, args.ip) else "[NOT FOUND]"
                print(f"{profile_name}: {status}")


if __name__ == "__main__":
    main()