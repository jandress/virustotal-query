import requests
import argparse
import time
import base64

API_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
API_URL_REPORT = "https://www.virustotal.com/api/v3/analyses/"
API_KEY = "YOUR_API_KEY_HERE"  # Replace with your actual API key

def scan_url(url):
    headers = {'x-apikey': API_KEY}
    data = {'url': url}
    response = requests.post(API_URL_SCAN, headers=headers, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error scanning URL {url}: {response.status_code}")
        print(response.text)
        return None

def get_report(analysis_id):
    headers = {'x-apikey': API_KEY}
    response = requests.get(f"{API_URL_REPORT}{analysis_id}", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching report for analysis ID {analysis_id}: {response.status_code}")
        print(response.text)
        return None

def read_urls(file_path):
    with open(file_path, 'r') as file:
        urls = file.readlines()
    return [url.strip() for url in urls]

def main():
    parser = argparse.ArgumentParser(description="Scan a list of URLs with VirusTotal.")
    parser.add_argument('file_path', help='Path to the file containing URLs to scan')
    args = parser.parse_args()

    urls = read_urls(args.file_path)
    print(f"Found {len(urls)} URLs to scan.")

    for url in urls:
        print(f"\nScanning URL: {url}")
        scan_result = scan_url(url)
        if scan_result:
            analysis_id = scan_result['data']['id']
            print(f"Analysis ID: {analysis_id}")
            
            print("Waiting for report...")
            time.sleep(30)  # Wait for a bit to allow VirusTotal to process the URL

            report = get_report(analysis_id)
            if report:
                print(f"Scan Report for {url}:")
                print(report)

if __name__ == "__main__":
    main()