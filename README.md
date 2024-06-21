# VirusTotal Query

`virustotal-query` is a Python script that scans a list of URLs using the VirusTotal API v3 and retrieves the scan reports.

## Features

- Scans URLs listed in a specified file.
- Retrieves and displays scan reports from VirusTotal.
- Uses VirusTotal API v3 for scanning and report retrieval.

## Requirements

- Python 3.x
- `requests` library

## Installation

1. Clone the repository:

2. Install the required dependencies:

3. Replace `YOUR_API_KEY_HERE` in `virustotal-query.py` with your actual VirusTotal API key.

## Usage

1. Create a file containing the URLs you want to scan, one URL per line. For example, `urls.txt`:


2. Run the script with the path to your file:

`python3 virustotal-query.py /path/to/your/urls.txt`