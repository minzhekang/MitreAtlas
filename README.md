# MitreAtlas

MITRE ATT&CK semantic mapping tool for detection coverage analysis.

MitreAtlas was created as a personal project to explore the feasibility of first-level semantic mapping between detection logic and MITRE ATT&CK techniques. The goal is to reduce the manual effort and time typically spent labeling detection use cases by leveraging semantic similarity.

While this tool is not intended to replace expert analysis, it aims to assist by providing a fast, high-level mapping to guide a further study and review.

> **Warning:**
> - This tool provides a general-purpose mapping between detection descriptions and MITRE ATT&CK techniques.
> - Results are meant to give a high-level sense of detection coverage and should not be considered definitive.
> - Further manual review and deeper analysis are essential to validate and contextualize these mappings before making any security decisions.
> 
> **Use at your own risk!**

## Showcase
![alt text](mitreatlas_animation_lossy.gif)

## How to use
### Features
- Semantic similarity between detection descriptions and MITRE techniques
- Coverage scoring per tactic
- SentenceTransformer model selection
- Integration with Mitre Navigator (WIP)
### Usage
MitreAtlas takes in a list of detection use cases (as a JSON file), semantically compares each description against the MITRE ATT&CK technique descriptions, and outputs the top-matched techniques per use case.

#### Input
The input JSON file should be a list of detection use cases in the following format:

```json
[
  {
    "name": "usecase1",
    "description": "User copies files to and executes programs from USB removable media"
  },
  {
    "name": "usecase2",
    "description": "User logs in to multiple systems with failed login attempts in short succession"
  }
]
```
Each usecase must include:
- name: A unique identifier for the usecase.
- description: A free-text explanation of the detection logic or behavior (can be human readable)

#### Output
The tool generates an output JSON file (output.json by default), structured like this:

```json
[
  {
    "usecase": "usecase1",
    "description": "User copies files to and executes programs from USB removable media",
    "matches": [
      {
        "id": "T1025",
        "name": "Data from Removable Media",
        "phases": [
          "collection"
        ],
        "score": 0.524
      },
      ...
    ]
  }
]
```
You can optionally disable scores using the -r flag.

## Quick Start
### Install dependencies
```bash
pip install -r requirements.txt
```
### Running the script
```bash
python mitreatlas.py -i input.json -s all-MiniLM-L6-v2
```
### Help options
```bash
options:
  -h, --help            show this help message and exit
  -s SEMANTIC_MODEL, --semantic_model SEMANTIC_MODEL
                        Choose semantic model, some available options are: [all-MiniLM-L6-v2, msmarco-distilbert-base-v4]. You can find the complete list here:
                        https://huggingface.co/models
  -i INPUT, --input INPUT
                        Input target json file *.json, example of the format is [ { "name": "usecase1", "description": "User copies files to and executes programs from USB
                        removable media" }, { "name": "usecase2", "description": "User logs in to multiple systems with failed login attempts in short succession" } ]
  -o OUTPUT, --output OUTPUT
                        Output target json file *.json
  -m MITREJSON, --mitrejson MITREJSON
                        Target Mitre Att&ck enterprise json file *.json
  -r, --removescore     Removes the score in the output file
  -d, --download        Download Mitre Att&ck enterprise json file from github
```