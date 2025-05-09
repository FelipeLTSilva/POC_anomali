ThreatStream to Halo Integration

This project automates the collection of threat intelligence from Anomali ThreatStream and creates tickets in Halo ITSM based on specific keywords.

Project structure:

├── threatstream-api.py: Main script that collects data via the Anomali ThreatStream API and creates tickets via the Halo ITSM API.

├── last_timestamp.txt: Stores the last timestamp used in the previous API call to avoid duplicates.

├── Jenkinsfile: Automation pipeline (e.g., daily execution).

├── README.md: This file.

