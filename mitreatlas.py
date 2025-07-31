"""
© 2025 Kang Min Zhe <kangminzhe2@gmail.com>
@MitreAtlas

Warning:
This tool provides a general-purpose mapping between detection descriptions and MITRE ATT&CK techniques. 
Results are meant to give a high-level sense of detection coverage and should not be considered definitive.
Further manual review and deeper analysis are essential to validate and contextualize these mappings before making any security decisions.
    
Use at your own risk!

"""

# Imports
import argparse
import logging
import sys
from pathlib import Path
import json
import pyfiglet
from collections import defaultdict
from tqdm import tqdm
from colorama import Fore, Style

# Example list of input usecases
usecases = [
    {
        "name": "usecase1",
        "description": "User copies files to and executes programs from USB removable media"
    },
    {
        "name": "usecase2",
        "description": "User logs in to multiple systems with failed login attempts in short succession"
    }
]

formatted_json = json.dumps(usecases, indent=2)

# Logger, we are mostly using info
def setup_logger(verbose: bool = False):
    if verbose:
        level = logging.DEBUG 
    else: 
        level = logging.INFO
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=level)
    return 0

# To print out the coverage results
def pretty_print(coverage_data):
    for tactic, stats in coverage_data.items():
        percent = stats["coverage_percent"]
        bar = tqdm(total=100, bar_format='{l_bar}{bar}| {n_fmt}%')
        bar.set_description(f"{Fore.YELLOW}{tactic:20s}{Style.RESET_ALL}")
        bar.update(percent)
        bar.close()
        print(f"{Fore.BLUE}Matched {stats['matched']}/{stats['total']} sub-techniques ({percent:.2f}%)\n{Style.RESET_ALL}")

# Download from github for the latest enterprise-attack json file
def download_file():
    import requests
    
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json"
    output_file = "enterprise-attack.json"
    
    logging.info(f"Downloading file from {url}")
    response = requests.get(url)
    
    with open(output_file, 'wb') as f:
        f.write(response.content)
    logging.info(f"Downloaded file saved to {output_file}")

# Checks if mitre file provided is valid
def check_mitre_json(mitre_file: str):
    file_path = Path(mitre_file)
    if file_path.is_file() and str(file_path).endswith(".json"):
        logging.info(f"{mitre_file} file is found! Proceeding with mappings.")
    else:
        logging.error(f"{mitre_file} is missing! Download the json file with -d option or manually from Mitre Att&ck website.")
        sys.exit(1)
    return 0

def check_output_file_exists(output_file: str):
    logging.info(f"Checking if {output_file} is already written...")
    file_path = Path(output_file)
    if file_path.is_file():
        response = input(f"[WARNING] File '{output_file}' already exists. Overwrite? (y/n): ").strip().lower()
        if response != 'y':
            logging.info("Exiting without overwriting.")
            sys.exit(0)
        else:
            logging.info("Overwriting file...")
    return 0

def check_input_file(input_file: str):
    logging.info(f"Checking if {input_file} is valid...")
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if not isinstance(data, list):
            logging.error(f"Please ensure that input json is in the format of: \n{formatted_json}")
            return False

        for item in data:
            if not isinstance(item, dict):
                logging.error(f"Please ensure that input json is in the format of: \n{formatted_json}")
                return False
                
            if 'name' not in item or 'description' not in item:
                logging.error(f"Please ensure that input json is in the format of: \n{formatted_json}")
                return False
            
        logging.info(f"{input_file} is valid!")    
        return True
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return False

def get_total_sub_techniques(mitrejson: json):
    
    objects = mitrejson['objects']
    # map tactic shortname to tactic name for reference
    tactics = {obj['x_mitre_shortname']: obj['name'] 
            for obj in objects if obj.get('type') == 'x-mitre-tactic'}

    # dictionary to count subtechniques per tactic
    subtechniques_count = defaultdict(int)

    # filter sub-techniques
    subtechniques = [obj for obj in objects if obj.get('type') == 'attack-pattern' and obj.get('x_mitre_is_subtechnique')]

    for subtech in subtechniques:
        kill_chain_phases = subtech.get('kill_chain_phases', [])
        for phase in kill_chain_phases:
            tactic_shortname = phase.get('phase_name')
            if tactic_shortname in tactics:
                subtechniques_count[tactic_shortname] += 1

    # Log the results for each sub-technique
    for tactic_shortname, count in subtechniques_count.items():
        logging.info(f"{tactics[tactic_shortname]} ({tactic_shortname}): {count} sub-techniques found!")

def load_subtechniques_by_tactic(mitre_data):
    tactic_to_subtechniques = defaultdict(set)

    for obj in mitre_data.get("objects", []):
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
            if obj.get("x_mitre_is_subtechnique", False):
                external_refs = obj.get("external_references", [])
                if external_refs and isinstance(external_refs, list):
                    external_id = external_refs[0].get("external_id")
                    phases = [p["phase_name"] for p in obj.get("kill_chain_phases", []) if "phase_name" in p]
                    for phase in phases:
                        tactic_to_subtechniques[phase].add(external_id)
    return tactic_to_subtechniques

# To extract the subtechnique after generating the results in a dictionary format for each tid
def extract_matched_subtechniques_by_tactic(results_json):
    matched = defaultdict(set)
    for entry in results_json:
        for match in entry["matches"]:
            tid = match["id"]
            if "." in tid: 
                for phase in match.get("phases", []):
                    matched[phase].add(tid)
    return matched


def calculate_coverage_per_tactic(mitre_json_file, results_json_file):
    logging.info(f"Calculating score for each technique...")

    with open(mitre_json_file, "r", encoding="utf-8") as f:
        mitre_data = json.load(f)

    with open(results_json_file, "r", encoding="utf-8") as f:
        results_data = json.load(f)

    total_subs = load_subtechniques_by_tactic(mitre_data)
    matched_subs = extract_matched_subtechniques_by_tactic(results_data)

    coverage = {}
    for tactic, total_ids in total_subs.items():
        matched_ids = matched_subs.get(tactic, set())
        score = (len(matched_ids) / len(total_ids)) * 100 if total_ids else 0
        coverage[tactic] = {
            "matched": len(matched_ids),
            "total": len(total_ids),
            "coverage_percent": round(score, 2)
        }

    return coverage

def extract_techniques(data):
    techniques = []
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
            external_id = obj.get("external_references", [{}])[0].get("external_id", "null")

            techniques.append({
                "id": external_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "phases": [phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", [])]
            })
    return techniques

def load_mitre_techniques(mitre_file: str):
    logging.info(f"Loading {mitre_file}...")
    
    try:
        with open(mitre_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        techniques = extract_techniques(data)
        get_total_sub_techniques(data)
        
                
    except Exception as e:
        logging.error(f"Error while loading Mitre Att&ck json file: {e}")
        sys.exit(1)

    logging.info(f"Loading complete!")
    return techniques



def mitre_semantic(input_file: str, output_file: str, semantic_model:str, remove_score: bool, techniques: list ):
    
    logging.info(f"Initializing sentence_transformers. Please be patient...")
    from sentence_transformers import SentenceTransformer, util
    logging.info(f"sentence_transformers loaded!")
    logging.info(f"Semantic model used: {semantic_model}")
    logging.info(f"Input JSON file: {input_file}")

    # The model that i've tested is mostly on all-MiniLM-L6-v2, which was giving me fairly decent results
    model = SentenceTransformer(f"{semantic_model}")

    # Loading of use case in JSON
    with open(input_file, "r", encoding="utf-8") as f:
        usecases = json.load(f)

    # Encode mitre descriptions, which converts it into a vector to capture semantic meaning
    technique_texts = [i["description"] for i in techniques]
    technique_embeddings = model.encode(technique_texts, convert_to_tensor=True)

    results = []

    for uc in usecases:
        logging.info(f'Parsing usecase: {uc["name"]}')
        detection_desc = uc["description"]
        detection_embedding = model.encode(detection_desc, convert_to_tensor=True)
        cos_scores = util.cos_sim(detection_embedding, technique_embeddings)[0]
        top_results = cos_scores.topk(5)

        matches = []
        for score, idx in zip(top_results.values, top_results.indices):
            tech = techniques[idx]
            if remove_score:
                matches.append({
                    "id": tech["id"],
                    "name": tech["name"],
                    "phases": tech.get("phases", [])
                })
            else:
                matches.append({
                    "id": tech["id"],
                    "name": tech["name"],
                    "phases": tech.get("phases", []),
                    "score": round(score.item(), 3)
                })

        results.append({
            "usecase": uc["name"],
            "description": detection_desc,
            "matches": matches
        })


    # Save results to JSON
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return 0

def main():
    parser = argparse.ArgumentParser(
        description= """
    """
    )
    parser.add_argument(
        "-s", "--semantic_model",
        help="Choose semantic model, some available options are: [all-MiniLM-L6-v2, msmarco-distilbert-base-v4]. You can find the complete list here: https://huggingface.co/models" ,
        default="all-MiniLM-L6-v2"
    )
    parser.add_argument(
        "-i", "--input",
        help=f"Input target json file *.json, example of the format is {formatted_json}",
        required=True
    )
    parser.add_argument(
        "-o", "--output",
        help="Output target json file *.json",
        default="output.json"
    )
    parser.add_argument(
        "-m", "--mitrejson",
        help="Target Mitre Att&ck enterprise json file *.json",
        default="enterprise-attack.json"
    )
    parser.add_argument(
        "-r", "--removescore",
        help="Removes the score in the output file",
        action="store_true"
    )
    parser.add_argument(
        "-d", "--download",
        help="Download Mitre Att&ck enterprise json file from github",
        action="store_true"
    )

    args = parser.parse_args()
    print("*-------------------------------------------------------*")
    print(Fore.BLUE + pyfiglet.figlet_format("MitreAtlas", font="small") + Style.RESET_ALL)
    print("""
*-------------------------------------------------------*
Warning:
This tool provides a general-purpose mapping between detection descriptions and MITRE ATT&CK techniques. 
Results are meant to give a high-level sense of detection coverage and should not be considered definitive.
Further manual review and deeper analysis are essential to validate and contextualize these mappings before making any security decisions.
    
Use at your own risk!
*-------------------------------------------------------*
    """)

    # Setup of loggerino
    setup_logger()
    
    try:
        
        if check_input_file(input_file=args.input):
            check_output_file_exists(output_file=args.output)
            if args.download:
                download_file()
            check_mitre_json(mitre_file = args.mitrejson)
            techniques = load_mitre_techniques(mitre_file = args.mitrejson)
            mitre_semantic(input_file = args.input,  
                        output_file =  args.output,
                        semantic_model =args.semantic_model,
                        remove_score = args.removescore,
                        techniques=techniques)
            
            results = (calculate_coverage_per_tactic(args.mitrejson, args.output))
            pretty_print(results)
            logging.info(f"Mitre Atlas has completed its job.\n You may check for the generated results here: {args.output}.\n\n Exiting silently now...")
            sys.exit(0)
    
    except Exception as e:
        logging.error(f"Error while parsing file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
