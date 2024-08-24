import requests
import json

# GitHub Repository details
owner = 'cpriyakant'
repo = 'Python-Demo'
token = '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' #Only Read Access to code scanning Alerts for the above repo

# CWE API endpoint template
cwe_api_url = 'https://cwe-api.mitre.org/api/v1/cwe/weakness/'

# GitHub API endpoint for code scanning alerts
url = f'https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts'

# Headers with authentication
headers = {
    'Authorization': f'token {token}',
    'Accept': 'application/vnd.github.v3+json'
}

def fetch_cwe_details(cwe_id):
    response = requests.get(f'{cwe_api_url}{cwe_id}')
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch CWE details for ID {cwe_id}. Status code: {response.status_code}")
        return None

def main():
    # Make a request to the GitHub API
    response = requests.get(url, headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        alerts = response.json()

        # Filter for high and critical severity alerts
        high_critical_alerts = [
            alert for alert in alerts 
            if alert['rule']['security_severity_level'] in ['critical', 'high']
        ]

        if high_critical_alerts:
            print(f"\nFound {len(high_critical_alerts)} critical or high severity alerts:")
            print("Printing list of vulnerabilities with severity High or above AND 'Likelihood of exploitability High or above ")
            for alert in high_critical_alerts:
                cwe_tags = [
                    tag.split('cwe-')[-1] for tag in alert['rule']['tags']
                    if tag.startswith('external/cwe/cwe-')
                ]
                cwe_tags = [int(tag) for tag in cwe_tags]

                # Fetch CWE details and check LikelihoodOfExploit
                cwe_valid = False
                for cwe_id in cwe_tags:
                    cwe_details = fetch_cwe_details(cwe_id)
                    if cwe_details and 'Weaknesses' in cwe_details:
                        likelihood_of_exploit = cwe_details['Weaknesses'][0].get('LikelihoodOfExploit')
                        if likelihood_of_exploit == 'High':
                            cwe_valid = True
                            break

                if cwe_valid:
                    print(f"\nRule Description: {alert['rule']['description']}")
                    print(f"Alert Number: {alert['number']}")
                    print(f"Created At: {alert['created_at']}")
                    print(f"State: {alert['state']}")                    
                    print(f"Security Severity Level: {alert['rule']['security_severity_level']}")
                    # Print CWE Tags as an array of numeric values
                    cwe_tags = [int(tag) for tag in cwe_tags]
                    print(f"CWE Tags: {cwe_tags}")
                    print(f"Full Description: {alert['rule']['full_description']}")
                    print(f"Tool Name: {alert['tool']['name']}")
                    print(f"File Path: {alert['most_recent_instance']['location']['path']}")
                    print(f"Start Line: {alert['most_recent_instance']['location']['start_line']}")
                    print(f"End Line: {alert['most_recent_instance']['location']['end_line']}")
        else:
            print("No high or critical severity alerts found.")
    else:
        print(f"Failed to fetch alerts. Status code: {response.status_code}")
        print(response.text)

if __name__ == '__main__':
    main()