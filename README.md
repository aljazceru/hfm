# Hetzner Firewall Manager

A Python tool to manage Hetzner Robot Firewall configurations via the API.

## Features

- Import existing firewall configurations from all your Hetzner servers
- Add your current public IP to all servers with one command  
- Add/remove specific IPs across all servers
- Verify that changes are actually applied
- Maintain a local configuration file for easy management

## Installation

1. Install dependencies:
```bash
pip install requests python-dotenv
```

2. Create a `.env` file with your Hetzner Robot credentials:
```bash
HETZNER_USER=your_username
HETZNER_PASS=your_password
```

## Quick Start

1. **Import existing firewall configurations:**
```bash
python3 hfw.py bootstrap
```

2. **Add your current IP to all servers:**
```bash
python3 hfw.py whitelist-current --comment "Home office"
```

3. **Verify the IP was added:**
```bash
python3 hfw.py whitelist-current --comment "Home office" --verify
```

## Usage

### Commands

#### Bootstrap - Import existing configurations
```bash
python3 hfw.py bootstrap
```
Imports all existing firewall configurations from your Hetzner servers.

#### Whitelist Current IP
```bash
python3 hfw.py whitelist-current [options]
  --comment, -c    Comment for the IP (default: "Current location")
  --verify, -v     Verify the IP was added
```
Automatically detects your current public IP and adds it to all servers.

#### Remove Current IP
```bash
python3 hfw.py remove-current [options]
  --verify, -v     Verify the IP was removed
```
Automatically detects your current public IP and removes it from all servers.

#### Add Specific IP
```bash
python3 hfw.py add <ip> [options]
  --comment, -c    Comment for the IP
  --profile, -p    Specific profile (default: all)
```
Example:
```bash
python3 hfw.py add 203.0.113.10 --comment "Office"
```

#### Remove IP
```bash
python3 hfw.py remove <ip> [options]
  --profile, -p    Specific profile (default: all)
```
Example:
```bash
python3 hfw.py remove 203.0.113.10
```

#### List Profiles
```bash
python3 hfw.py list
```
Shows all configured server profiles.

#### List Whitelisted IPs
```bash
python3 hfw.py list-ips [options]
  --profile, -p    Specific profile (default: all)
```
Shows all whitelisted IPs for each server.

#### Verify IP
```bash
python3 hfw.py verify <ip>
```
Checks if an IP is whitelisted on all servers.

## Configuration File

The tool maintains a `firewall_config.json` file with your server profiles and whitelisted IPs. This file is created automatically when you run `bootstrap`.

Example structure:
```json
{
  "profiles": {
    "web-server": {
      "server_ip": "203.0.113.1",
      "server_name": "web-server",
      "permanent_whitelist": [
        {
          "ip": "198.51.100.5/32",
          "ports": [],
          "comment": "Office"
        }
      ],
      "filter_ipv6": false,
      "whitelist_hos": true
    }
  }
}
```

## Common Workflows

### Initial Setup
```bash
# 1. Set up credentials
echo "HETZNER_USER=your_username" > .env
echo "HETZNER_PASS=your_password" >> .env

# 2. Import existing configurations
python3 hfw.py bootstrap

# 3. Add your current IP
python3 hfw.py whitelist-current --comment "Home" --verify
```

### Daily Usage - Working from Different Locations
```bash
# When working from a new location, simply run:
python3 hfw.py whitelist-current --comment "Coffee shop" --verify

# When leaving a location, remove your IP:
python3 hfw.py remove-current --verify
```

### Managing Office IPs
```bash
# Add office IP to all servers
python3 hfw.py add 203.0.113.10 --comment "Main office"

# Remove old office IP
python3 hfw.py remove 198.51.100.5
```

## Important Notes

- Changes may take 20-30 seconds to apply on Hetzner servers
- The tool preserves all existing firewall rules
- Always maintain at least one permanent IP with SSH access as a fallback
- The API uses URL-encoded format, not JSON

## Troubleshooting

### Changes not applying
- Wait at least 30 seconds for changes to propagate
- Use the `--verify` flag to confirm changes are applied
- Check that the server has a firewall configured in the Hetzner Robot panel

### Authentication issues
- Verify your credentials in the `.env` file
- Ensure you're using Robot API credentials, not Cloud API

### No servers found
- Check that your servers have firewalls configured
- Verify your account has access to the servers

## Security

- Never commit the `.env` file to version control
- Keep your `firewall_config.json` secure as it contains server information
- Always test firewall changes carefully to avoid locking yourself out
- Maintain at least one permanent IP with SSH access


