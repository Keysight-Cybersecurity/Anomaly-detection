## AI anomalydetection system (5G NAS )
This repository contains the necessary code for feature extraction and machine learning models to detect various attack types in 5G NAS (Non-Access Stratum) messages, including replay attacks, invalid UE capabilities, and malformed headers. The detection system uses 2 algorithms such as Isolation Forest and One-Class SVM. The field extractor file is written in Python. The Captured packet ".pcap" is parse into the function which helps to extract these fields as features into a structured CSV format for model training/testing.

## Repository Structure
This repository contains 5 main files such as

1. Invalid UE Capability Detection Model (UEcapabilityDectection.ipynb)

Detects invalid or malicious UE security capabilities per 3GPP TS 24.501
- Identifies missing mandatory algorithms (EA1/EA2, IA1/IA2)
- Detects all-zero capability attacks
- Flags NULL-only encryption/integrity

2.  Replay Attack Detection Model (replayDetection.ipynb)
Detects replayed NAS messages based on sequence number reuse, thesame procedureCode, the same Type, thesame session time, different timestamps 

3.  Invalid Header Detection Model (invalid_message_detector.py)
Detects protocol violations and invalid NAS headers

- Validates message types against 5GMM standards
- Checks EPD, security headers, and spare fields

4.  NAS Field Extractor (ExtractField.py)
Extracts NAS message fields from PCAP files for general analysis. Features such as

- Extracts key fields: EPD, SecHdr, Type, Sequence numbers, Time, AMF_UE_NGAP_ID, ip_source, procedureCode
- Handles nested NAS messages recursively
- Exports to CSV format for ML model training

5. UE Capability Extractor (ExtractUE_Capability.py)
Specialized extractor for UE security capability information. Extracts:

- 5G Encryption Algorithm (EA) capabilities
- 5G Integrity Algorithm (IA) capabilities
- Handles nested NAS messages recursively
- Exports to CSV format for ML model training


## Requirements

- Python 3.7

### Required Python Packages

- pyshark  
- pandas  
- numpy  
- scikit-learn  
- matplotlib  
- seaborn  
- joblib



### please make sure to install wireshark (required by pyshark) 
- Ubuntu/Debian: sudo apt-get install wireshark
- Windows: Download from wireshark.org

### install jupyter notebook on vscode
- pip install notebook 
- Go to Extensions (Ctrl+Shift+X) - > Search for and install (Python , Jupyter notebook)
- Create or Open a .ipynb file
- Press Ctrl+Shift+P → type and select "Python: Select Interpreter"
- Choose the interpreter where you installed Jupyter

## Usage
### Step 1: Feature Extraction
First, extract features from your PCAP files using the appropriate extractor:

- Place your PCAP files in the pcap/ directory
- CONFIG = {
    'capture_files': ['pcap/benign_traffic.pcap'],
    'output_file': 'extracted_features.csv',
    'delimiter': ';',
    'display_filter': 'nas-5gs and not http and not http2 and not http3 and not json'
}

- Run the extraction


### Step 2: Attack Detection model
- Replay Attack Detection
- Invalid UE Capability Detection
- Invalid Header Detection

#### Train the model
- train dataBenign.csv (Clean 5G NAS messages for baseline behavior)

#### Test on suspicious data
- dataMalicious.csv (To detect behaviour that deviates from the normal pattern)
- 5GSIDTest.csv (To detect behaviour that deviates from the normal pattern)

## Project Workflow
PCAP Files → Feature Extractors → CSV Files → ML Models → Attack Detection


## Anomaly Detection Algorithms:

- Isolation Forest: Primary detector with contamination rates of 0.001-0.01
- One-Class SVM: Secondary detector with RBF kernel
- Ensemble Methods: Weighted voting to reduce false positives


## Optimization Strategy:

- Hyperparameter tuning using grid search

