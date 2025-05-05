import argparse
import logging
import pandas as pd
import requests
import os
import json
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# API Keys (Ideally, these should be sourced from environment variables or a secure configuration file)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")  # Example: export VIRUSTOTAL_API_KEY="your_api_key"
# Other API keys for other services (e.g., AbuseIPDB, etc.) can be added similarly

# List of threat intelligence feed URLs (example)
THREAT_FEEDS = [
    "https://urlhaus.abuse.ch/downloads/csv/",  # URLhaus
    # Add more threat feeds here
]

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Analyze URL reputation using threat intelligence feeds and VirusTotal.")
    parser.add_argument("url", help="The URL to analyze.")
    parser.add_argument("-o", "--output", help="Output file path (CSV format).", default="url_analysis_report.csv")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return parser

def is_valid_url(url):
    """
    Validates a URL to ensure it's properly formatted.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def check_url_against_threat_feeds(url, threat_feeds):
    """
    Checks a URL against a list of threat intelligence feeds.

    Args:
        url (str): The URL to check.
        threat_feeds (list): A list of threat intelligence feed URLs.

    Returns:
        list: A list of dictionaries, where each dictionary contains information about
              a match found in a threat feed.  Returns an empty list if no matches are found.
    """
    matches = []
    for feed_url in threat_feeds:
        try:
            logging.info(f"Checking against threat feed: {feed_url}")
            response = requests.get(feed_url)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            # Simple string matching (can be improved with regular expressions)
            if url in response.text:
                logging.warning(f"URL found in threat feed: {feed_url}")
                matches.append({"feed": feed_url, "match_type": "exact", "confidence": "high"}) #customize confidence level later based on feed.
            else:
                logging.debug(f"URL not found in threat feed: {feed_url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching threat feed from {feed_url}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while processing {feed_url}: {e}")
    return matches

def analyze_url_with_virustotal(url, api_key):
    """
    Analyzes a URL using the VirusTotal API.

    Args:
        url (str): The URL to analyze.
        api_key (str): The VirusTotal API key.

    Returns:
        dict: A dictionary containing the VirusTotal analysis results. Returns None if an error occurs.
    """
    if not api_key:
        logging.warning("VirusTotal API key is not set. Skipping VirusTotal analysis.")
        return None

    url_id = requests.utils.quote(url)
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        json_response = response.json()
        logging.debug(f"VirusTotal API Response: {json_response}") # Log the full response for debugging

        if "data" in json_response:
            return json_response["data"]
        elif "error" in json_response:
            logging.error(f"VirusTotal API Error: {json_response['error']}")
            return None
        else:
            logging.error(f"Unexpected VirusTotal API response: {json_response}")
            return None

    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying VirusTotal API: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding VirusTotal API response: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during VirusTotal analysis: {e}")
        return None

def main():
    """
    Main function to orchestrate the URL analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url
    output_file = args.output

    if not is_valid_url(url):
        logging.error(f"Invalid URL: {url}")
        print("Error: Invalid URL. Please provide a valid URL.")
        return  # Exit the program

    logging.info(f"Analyzing URL: {url}")

    # Perform analysis
    threat_feed_matches = check_url_against_threat_feeds(url, THREAT_FEEDS)
    virustotal_analysis = analyze_url_with_virustotal(url, VIRUSTOTAL_API_KEY)

    # Prepare data for output
    report_data = {
        "url": url,
        "threat_feed_matches": threat_feed_matches,
        "virustotal_analysis": virustotal_analysis
    }

    # Create a Pandas DataFrame
    df = pd.DataFrame([report_data])

    # Convert the complex columns to string representation for CSV export
    df['threat_feed_matches'] = df['threat_feed_matches'].apply(lambda x: json.dumps(x))
    df['virustotal_analysis'] = df['virustotal_analysis'].apply(lambda x: json.dumps(x) if x is not None else None)


    # Export to CSV
    try:
        df.to_csv(output_file, index=False)
        logging.info(f"Analysis report saved to: {output_file}")
        print(f"Analysis report saved to: {output_file}")
    except Exception as e:
        logging.error(f"Error writing to CSV file: {e}")
        print(f"Error writing to CSV file: {e}")
        return


if __name__ == "__main__":
    main()


# Usage Examples:
# 1. Basic usage: python main.py https://www.example.com
# 2. Verbose output: python main.py https://www.example.com -v
# 3. Specify output file: python main.py https://www.example.com -o my_report.csv
# 4. With VirusTotal API key set as environment variable:
#    export VIRUSTOTAL_API_KEY="your_api_key"
#    python main.py https://www.example.com