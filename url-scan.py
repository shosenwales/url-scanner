import argparse
import requests
import os

API_KEY = ''


def check_url(url):
    try:
        # Send GET request to VirusTotal API with the URL and API key
        response = requests.get(f'https://www.virustotal.com/vtapi/v2/url/report?apikey={API_KEY}&resource={url}')

        # Check if the request was successful
        if response.status_code == 200:
            result = response.json()

            # Check the response code from VirusTotal
            if result['response_code'] == 1:
                positives = result['positives']
                total = result['total']

                print(f"URL: {url}")
                print(f"Detection ratio: {positives}/{total}")

                # Determine if the URL is likely malicious based on the number of positives
                if positives > 0:
                    print("The URL is likely malicious.")
                else:
                    print("The URL is not malicious.")

            elif result['response_code'] == 0:
                print("The URL is not in the VirusTotal database.")
            else:
                print("Error occurred during URL scanning.")
        else:
            print("Error occurred while connecting to VirusTotal.")

    except requests.exceptions.RequestException as e:
        print("An error occurred:", str(e))


if __name__ == "__main__":
    # Create argument parser
    parser = argparse.ArgumentParser(description="URL Checker Script")
    parser.add_argument("url", type=str, help="URL to check")

    # Parse command-line arguments
    args = parser.parse_args()

    # Call check_url function with the provided URL
    check_url(args.url)
