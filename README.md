# Juniper SRX Security Policy Automation

A Python-based automation tool for managing security policies on Juniper SRX firewalls using PyEZ (junos-eznc). This solution supports multi-device deployments with YAML-driven configuration management.

## Features

- ✅ **Multi-Device Support** - Deploy policies to multiple SRX firewalls simultaneously
- ✅ **YAML-Driven Configuration** - Easy-to-manage device inventory and policy definitions
- ✅ **Safe Commits** - Configuration diff preview before committing changes
- ✅ **Duplicate Detection** - Automatically checks if policies already exist
- ✅ **Audit Trail** - Commit comments for tracking changes
- ✅ **Post-Deployment Verification** - Validates policies after deployment
- ✅ **Comprehensive Error Handling** - Graceful handling of connection and configuration errors
- ✅ **Exclusive Configuration Mode** - Prevents configuration conflicts

## Prerequisites

### Software Requirements
- Python 3.7 or higher
- Juniper SRX firewall with NETCONF enabled
- SSH/NETCONF access to SRX devices

### Python Dependencies
```bash
pip install junos-eznc pyyaml
```

### SRX Configuration Requirements
Enable NETCONF on your SRX devices:
```bash
set system services netconf ssh
commit
```

## Project Structure

```
srx-automation/
├── juniper_srx_policy.py    # Main Python automation script
├── devices.yaml             # Device inventory file
├── policies.yaml            # Security policy definitions
└── README.md                # This file
```

## Installation

1. **Clone or download the project files**
   ```bash
   mkdir juniper_srx_policy
   cd juniper_srx_policy
   ```

2. **Install required Python packages**
   ```bash
   pip install junos-eznc pyyaml
   ```

3. **Configure your environment**
   - Edit `devices.yaml` with your SRX firewall details
   - Edit `policies.yaml` with your security policies

## Configuration

### devices.yaml

Define your SRX firewall inventory:

```yaml
- host: 192.168.1.1
  user: admin
  password: password

- host: 192.168.1.2
  user: admin
  password: password

- host: srx-branch-01.company.com
  user: netops
  password: SecurePass123
```

### policies.yaml

Define your security policies:

```yaml
- from_zone: trust
  to_zone: untrust
  policy_name: allow-web
  source_addresses: [any]
  destination_addresses: [any]
  applications: [junos-http, junos-https]
  action: permit
  log_session_init: true
  log_session_close: true
  description: Allow HTTP and HTTPS traffic

- from_zone: untrust
  to_zone: dmz
  policy_name: allow-ssh-mgmt
  source_addresses: [mgmt-network]
  destination_addresses: [server-01]
  applications: [junos-ssh]
  action: permit
  log_session_init: true
  description: Allow SSH from management to server
```

### Policy Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `from_zone` | Yes | - | Source security zone |
| `to_zone` | Yes | - | Destination security zone |
| `policy_name` | Yes | - | Unique policy name |
| `source_addresses` | No | `[any]` | List of source addresses/address-sets |
| `destination_addresses` | No | `[any]` | List of destination addresses/address-sets |
| `applications` | No | `[any]` | List of applications (e.g., junos-http) |
| `action` | No | `permit` | Policy action: permit, deny, or reject |
| `log_session_init` | No | `false` | Log session initiation |
| `log_session_close` | No | `false` | Log session closure |
| `description` | No | - | Policy description |

## Usage

### Basic Execution

Run the automation script:
```bash
python3 juniper_srx_policy.py
```

### Expected Output

```
======================================================================
 JUNIPER SRX SECURITY POLICY AUTOMATION (PyEZ)
======================================================================

=== Processing Device: 192.168.1.1 ===

🔹 Device: 192.168.1.1
🔹 Policy: allow-web
----------------------------------------------------------------------
Configuration diff:
======================================================================
[edit security policies from-zone trust to-zone untrust]
+    policy allow-web {
+        match {
+            source-address any;
+            destination-address any;
+            application [ junos-http junos-https ];
+        }
+        then {
+            permit;
+            log {
+                session-init;
+                session-close;
+            }
+        }
+    }
======================================================================
✅ Policy 'allow-web' committed successfully!

======================================================================
Verification: allow-web @ 192.168.1.1
======================================================================
policy allow-web {
    match {
        source-address any;
        destination-address any;
        application [ junos-http junos-https ];
    }
    then {
        permit;
        log {
            session-init;
            session-close;
        }
    }
}
======================================================================

✅ All tasks completed successfully!
```

## Common Use Cases

### Use Case 1: Deploy Standard Policies to Multiple Sites

**Scenario:** You have 10 branch offices with SRX firewalls that need identical security policies.

**Solution:**
1. Add all 10 devices to `devices.yaml`
2. Define standard policies in `policies.yaml`
3. Run once: `python3 juniper_srx_policy.py`

Result: All 10 firewalls receive the same policies automatically.

### Use Case 2: Add a New Policy to All Firewalls

**Scenario:** You need to allow a new application across your entire SRX fleet.

**Solution:**
1. Add the new policy to `policies.yaml`
2. Run: `python3 juniper_srx_policy.py`

Result: The new policy is added to all devices. Existing policies are skipped (duplicate detection).

### Use Case 3: Standardize Security Configuration

**Scenario:** Ensure consistent security posture across all SRX devices.

**Solution:**
1. Define your security baseline in `policies.yaml`
2. Maintain device inventory in `devices.yaml`
3. Run regularly or as part of CI/CD pipeline

Result: Configuration drift is eliminated, all devices maintain standard policies.

## Verification

### Manual Verification on SRX

Check deployed policies:
```bash
show security policies
show security policies from-zone trust to-zone untrust
show security policies hit-count
show configuration security policies | display set
```

### View Commit History
```bash
show system commit
show configuration | compare rollback 1
```

## Security Best Practices

### 1. Protect Credentials

**Option A: Environment Variables**
```python
import os

devices = [{
    "host": os.getenv("SRX_HOST"),
    "user": os.getenv("SRX_USER"),
    "password": os.getenv("SRX_PASS")
}]
```

```bash
export SRX_HOST=192.168.1.1
export SRX_USER=admin
export SRX_PASS=password
python3 juniper_srx_policy.py
```

**Option B: Ansible Vault**
```bash
ansible-vault encrypt devices.yaml
ansible-vault edit devices.yaml
```

**Option C: SSH Key Authentication**
```python
with Device(host=host, user=username, ssh_private_key_file="/path/to/key") as dev:
    # Your code here
```

### 2. Use Dedicated Automation User

Create a dedicated user on SRX with appropriate permissions:
```bash
set system login user automation class super-user
set system login user automation authentication plain-text-password
commit
```

### 3. Enable NETCONF Only for Management Network

```bash
set system services netconf ssh connection-limit 5
set system services netconf ssh rate-limit 5
# Restrict to management network
set interfaces lo0 unit 0 family inet filter input management-access
commit
```

## Troubleshooting

### Connection Errors

**Problem:** `✗ Connection Error: ConnectAuthError`

**Solution:**
- Verify SSH connectivity: `ssh admin@192.168.1.1`
- Check NETCONF is enabled: `show configuration system services netconf`
- Verify credentials in `devices.yaml`

### Configuration Load Errors

**Problem:** `✗ Config Load Error: statement not found`

**Solution:**
- Verify address-book entries exist before referencing them
- Check application names are valid (use `show applications` on SRX)
- Ensure zones exist: `show security zones`

### Commit Errors

**Problem:** `✗ Commit Error: configuration check-out failed`

**Solution:**
- Another user may have configuration locked
- Check: `show system commit`
- Clear lock if needed: `configure private`

### Policy Already Exists

**Message:** `⚠️ Policy 'allow-web' already exists. Skipping...`

**This is normal behavior** - The script detects duplicate policies and skips them. If you need to modify an existing policy:
1. Delete it first manually, or
2. Modify the script to delete before adding, or
3. Use a different policy name

## Execution Flow

```
┌─────────────────────────────────────────┐
│  Load devices.yaml & policies.yaml      │
└──────────────┬──────────────────────────┘
               │
               ▼
      ┌────────────────┐
      │ For each device│
      └────────┬───────┘
               │
               ▼
        ┌──────────────┐
        │ For each     │
        │ policy       │
        └──────┬───────┘
               │
               ▼
    ┌──────────────────────┐
    │ Check if policy      │
    │ already exists       │
    └──────┬───────────────┘
           │
           ▼
    ┌──────────────────────┐
    │ Build set commands   │
    └──────┬───────────────┘
           │
           ▼
    ┌──────────────────────┐
    │ Load configuration   │
    └──────┬───────────────┘
           │
           ▼
    ┌──────────────────────┐
    │ Show diff            │
    └──────┬───────────────┘
           │
           ▼
    ┌──────────────────────┐
    │ Commit with comment  │
    └──────┬───────────────┘
           │
           ▼
    ┌──────────────────────┐
    │ Verify policy        │
    └──────────────────────┘
```

## Rollback

If you need to rollback changes:

### Automatic Rollback (SRX Feature)
```bash
# On SRX device
rollback 1
commit
```

### Script-Based Rollback
Add this function to `juniper_srx_policy.py`:
```python
def rollback_changes(host, username, password, rollback_id=1):
    """Rollback to previous configuration"""
    try:
        with Device(host=host, user=username, passwd=password) as dev:
            with Config(dev, mode="exclusive") as cu:
                cu.rollback(rollback_id)
                cu.commit(comment=f"Rollback to version {rollback_id}")
                print(f"✅ Rolled back to configuration version {rollback_id}")
    except Exception as err:
        print(f"✗ Rollback failed: {err}")
```

## Testing

### Test in Lab Environment First

1. Set up a lab SRX (physical or virtual)
2. Test with non-production policies
3. Verify rollback procedures work
4. Document any site-specific requirements

### Dry-Run Mode (Future Enhancement)

Add this to the script for testing without committing:
```python
if DRY_RUN:
    print("DRY RUN MODE - Changes not committed")
else:
    cu.commit(comment=f"Added policy: {policy_name}")
```

## Common Junos Applications

Use these built-in application names in your policies:

| Application | Description |
|-------------|-------------|
| `junos-http` | HTTP (TCP 80) |
| `junos-https` | HTTPS (TCP 443) |
| `junos-ssh` | SSH (TCP 22) |
| `junos-telnet` | Telnet (TCP 23) |
| `junos-ftp` | FTP (TCP 21) |
| `junos-smtp` | SMTP (TCP 25) |
| `junos-dns-udp` | DNS (UDP 53) |
| `junos-dns-tcp` | DNS (TCP 53) |
| `junos-ping` | ICMP Echo |
| `junos-icmp-all` | All ICMP |
| `junos-ms-sql` | MS SQL (TCP 1433) |
| `junos-mysql` | MySQL (TCP 3306) |
| `any` | All applications |

View all applications:
```bash
show applications
```

## Contributing

Contributions are welcome! Areas for enhancement:

- [ ] Add dry-run mode
- [ ] Implement logging to file
- [ ] Add policy deletion functionality
- [ ] Support for policy schedules
- [ ] Integration with version control (Git)
- [ ] CI/CD pipeline examples
- [ ] Ansible playbook version
- [ ] Support for address-book management
- [ ] Policy ordering/insertion at specific positions

## License

This project is provided as-is for educational and automation purposes.

## Author

**Ehsan Momeni Bashusqeh** - Network Automation Engineer

## Support

For issues or questions:
1. Check the Troubleshooting section
2. Review Juniper PyEZ documentation: https://www.juniper.net/documentation/product/us/en/junos-pyez/
3. Check YAML syntax: https://yaml.org/

## References

- [Juniper PyEZ Documentation](https://www.juniper.net/documentation/product/us/en/junos-pyez/)
- [Juniper SRX Security Policies](https://www.juniper.net/documentation/us/en/software/junos/security-policies/index.html)
- [YAML Syntax](https://yaml.org/spec/1.2.2/)
- [Python junos-eznc GitHub](https://github.com/Juniper/py-junos-eznc)

---

**Important Notes:**
- Always test in a lab environment first
- Keep backups of your configurations
- Use version control for your YAML files
- Implement proper credential management
- Schedule maintenance windows for production changes
- Document all changes in commit comments

**Happy Automating!**
