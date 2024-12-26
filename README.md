# Prisma Cloud Attack Path CVE Reporter

This script analyzes resources with active Attack Path Policies in Prisma Cloud and generates a detailed report of associated CVEs.

## Prerequisites

* Python 3.x
* `requests` package installed
* Prisma Cloud access (API key and secret)

## Quick Start (Linux)

1. Clone the repository:
```bash
git clone https://github.com/yourusername/prisma-ap-cve.git
cd prisma-ap-cve
```


2. Update the `config.py` file with your credentials:
```python
url = "api2.prismacloud.io"  # Your Prisma Cloud API URL
api_key = "your_access_key_here"
api_secret = "your_secret_key_here"
```

3. Make the script executable and run:
```bash
chmod +x AttackPathCVE.py
./AttackPathCVE.py         # Default 12 months of data
./AttackPathCVE.py 6       # Or specify number of months (e.g., 6)
```

## Output

The script generates:

1. **CSV File** (`prisma_attack_paths_TIMESTAMP.csv`) containing:
   * Resource details (Name, ID, Type, Region)
   * Attack Path ID
   * CVE information (ID, Severity, CVSS Score)

2. **Console Summary** showing:
   * Resources with CVEs and their details
   * List of resources without CVEs
   * Total count statistics

## Common Issues

1. **Authentication Errors**: Verify your API credentials in `config.py`
2. **Permission Issues**: Ensure your API key has necessary permissions
3. **No Data**: Check the time range and policy filters

## Note

* this is an unofficial prisma cloud script. we are only reading info from the console, nothing will be updated
* contact: aquadri@paloaltonetworks.com
