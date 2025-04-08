#!/usr/bin/env python
# SFA_VectorEyes.py
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "requests",
#     "tqdm",
#     "sentence-transformers",
#     "regex",
#     "rich",
#     "numpy",
#     "ollama>=0.1.6"
# ]
# ///

"""
SFA_VectorEyes - Vulnerability Report Vectorisation & Detection Library Builder

Features:
1. Accept a URL (Markdown file or GitHub repo) for a vulnerability report.
2. Download, embed, and call a local LLM to extract:
   • Vulnerability type (with CWE if available)
   • Three key security research questions
   • Dual code snippets (vulnerable/fixed)
   • Researcher insights
3. Save the report data (and a detection pattern) in a SQLite DB.
4. Build a comprehensive detection library by aggregating reports per vulnerability category.
5. Use the LLM to generate robust aggregated detection templates.
6. Save the aggregated library and robust detection templates to a new table in the database.
7. View the detection library.
8. Delete one or all detection library entries.
"""

import os, sys, time, json, sqlite3, hashlib, threading, requests, re, numpy as np
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import ollama  # Import the ollama-python client

# Simplified API key management (session-only, not saved to disk)
# No longer using external api_keys module for more secure API key handling
print("Using secure session-based API key management")
# Removing SentenceTransformer dependency to avoid compatibility issues
# from sentence_transformers import SentenceTransformer
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.align import Align
from rich.box import SIMPLE

# ---------------------- Global & Console Setup ----------------------
DB_PATH = "vectorisation.db"
console = Console()
task_status = {}    # For background task statuses
task_lock = threading.Lock()

# ---------------------- Database Functions ----------------------
def init_db():
    """Initialize the main reports and patterns tables."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            source TEXT,
            content TEXT,
            overall_embedding TEXT,
            section_embeddings TEXT,
            analysis_summary TEXT,
            metadata TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS patterns (
            report_id TEXT PRIMARY KEY,
            pattern TEXT
        )
    ''')
    # Detection library table for aggregated robust templates
    c.execute('''
        CREATE TABLE IF NOT EXISTS detection_library (
            vuln_type TEXT PRIMARY KEY,
            details TEXT,
            template TEXT
        )
    ''')
    conn.commit()
    conn.close()
    
    # Create cache directory for API responses
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, exist_ok=True)

def save_report(report_id, source, content, overall_embedding, section_embeddings, analysis_summary, metadata):
    """Save a processed report into the reports table."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO reports 
        (id, source, content, overall_embedding, section_embeddings, analysis_summary, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        report_id,
        source,
        content,
        json.dumps(overall_embedding),
        json.dumps(section_embeddings),
        json.dumps(analysis_summary),
        json.dumps(metadata)
    ))
    conn.commit()
    conn.close()

def save_pattern(report_id, pattern):
    """Save a detection pattern (extracted from analysis) to the patterns table."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO patterns
        (report_id, pattern)
        VALUES (?, ?)
    ''', (report_id, pattern))
    conn.commit()
    conn.close()

def view_reports():
    """Display all processed reports in a table."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, source, metadata FROM reports")
    rows = c.fetchall()
    conn.close()
    if not rows:
        console.print("[yellow]No reports found.[/yellow]")
        return
    table = Table(title="Vectorized Reports", show_lines=True)
    table.add_column("Report ID", style="cyan")
    table.add_column("Source", style="magenta")
    table.add_column("Downloaded At", style="green")
    for row in rows:
        try:
            metadata = json.loads(row[2])
            downloaded_at = metadata.get("downloaded_at", "N/A")
        except Exception:
            downloaded_at = "N/A"
        table.add_row(row[0], row[1], downloaded_at)
    console.print(table)

def delete_report(report_id: str):
    """Delete a single report and its associated pattern."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM reports WHERE id=?", (report_id,))
    c.execute("DELETE FROM patterns WHERE report_id=?", (report_id,))
    conn.commit()
    conn.close()

def delete_all_reports():
    """Delete all reports and associated patterns."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM reports")
    c.execute("DELETE FROM patterns")
    conn.commit()
    conn.close()

def delete_reports():
    """Prompt to delete a single report or all reports."""
    choice = console.input("Delete a single report or all reports? (single/all): ").strip().lower()
    if choice == "single":
        report_id = console.input("Enter the Report ID to delete: ").strip()
        delete_report(report_id)
        console.print(f"[green]Deleted report {report_id}.[/green]")
    elif choice == "all":
        confirm = console.input("Are you sure you want to delete ALL reports? (Y/N): ").strip().lower()
        if confirm == "y":
            delete_all_reports()
            console.print("[green]All reports deleted.[/green]")
        else:
            console.print("[yellow]Deletion cancelled.[/yellow]")
    else:
        console.print("[red]Invalid choice. No reports deleted.[/red]")

# ---------------------- Utility Functions ----------------------
def download_markdown(url: str) -> str:
    """Download a Markdown file from a URL; adjust URL if GitHub blob."""
    if "github.com" in url and "/blob/" in url:
        url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    try:
        r = requests.get(url)
        return r.text if r.status_code == 200 else None
    except Exception:
        return None

def compute_embedding(text: str, model_instance=None) -> list:
    """Compute a simple hash-based embedding for text (fallback method)
    
    This is a simplified embedding that hashes the text and converts to vector.
    It's not as good as a proper embedding model but works without dependencies.
    """
    # Create a simpler representation based on hashing
    # This won't have the semantic properties of a real embedding, but can work for basic similarity
    if not text:
        return [0.0] * 64  # Return a zero vector if text is empty
    
    # Get a stable hash from the text
    h = hashlib.sha256(text.encode('utf-8')).digest()
    
    # Convert the 32-byte hash to 64 float values between -1 and 1
    # by treating each byte as two 4-bit values
    result = []
    for byte in h:
        # Extract the high 4 bits and low 4 bits
        high = (byte >> 4) & 0xF
        low = byte & 0xF
        # Convert to values between -1 and 1
        result.append((high / 7.5) - 1.0)  # -1.0 to 1.0
        result.append((low / 7.5) - 1.0)   # -1.0 to 1.0
    
    return result

def split_into_sections(text: str) -> list:
    """Split Markdown text into sections based on headings."""
    sections = text.split("\n#")
    results = []
    for sec in sections:
        if sec.strip():
            if sec.startswith("#"):
                sec = sec[1:]
            lines = sec.splitlines()
            title = lines[0].strip() if lines else "Introduction"
            content = "\n".join(lines[1:]).strip() if len(lines) > 1 else ""
            results.append({"title": title, "content": content})
    return results

def should_ignore_file(url: str) -> bool:
    """Ignore files with 'readme' in the URL."""
    return "readme" in url.lower()

def report_already_exists(report_id: str) -> bool:
    """Check if a report with the given ID already exists."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM reports WHERE id=?", (report_id,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

# ---------------------- LLM Analysis Functions ----------------------
# Ollama API settings
LLM_API_BASE = os.getenv("LLM_API_BASE", "http://localhost:11434")
# The ollama-python client handles these URLs internally
LLM_API_GENERATE = os.getenv("LLM_API_GENERATE", f"{LLM_API_BASE}/api/generate")
LLM_API_URL = os.getenv("LLM_API_URL", f"{LLM_API_BASE}/v1/completions")

# Configure Ollama client to use the right base URL
try:
    # Set the host for the ollama client
    ollama.host = LLM_API_BASE
except Exception as e:
    console.print(f"[yellow]Warning: Failed to configure Ollama client: {e}[/yellow]")

# Use API key management system if available
# Session-based API key management
# Initialize from environment variables or use defaults
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
USE_API = os.getenv("USE_API", "auto").lower()
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "deepseek/deepseek-r1-distill-llama-70b:free")
DEFAULT_OLLAMA_MODEL = os.getenv("DEFAULT_OLLAMA_MODEL", "deepseek-r1:32b")

# OpenRouter API URL and data policy setting
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_DATA_USAGE = "null"  # Set to 'null' to use models without sharing data

# Backup models for OpenRouter - matching DeepCurrent_v3.1.py model selection
BACKUP_MODELS = [
    "deepseek/deepseek-v3-base:free",
    "google/gemini-2.5-pro-exp-03-25:free",
    "mistralai/mistral-small-3.1-24b-instruct:free",
    "open-r1/olympiccoder-32b:free"
]

# Cache directory for responses
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "response_cache")

def generate_structured_analysis(report: str, model: str = DEFAULT_OLLAMA_MODEL) -> dict:
    """
    Call the LLM to extract structured vulnerability data from the report using an enhanced prompt
    that handles modern audit report formats better.
    
    Enhanced extraction includes:
      - 'vuln_type': The vulnerability type, with CWE and severity
      - 'questions': Security research questions that led to discovering the vulnerability
      - 'vulnerable_code': Code snippet demonstrating the vulnerability
      - 'fixed_code': Code showing how the vulnerability was fixed
      - 'researcher_insights': Summary of researcher insights and impact analysis
      - 'severity_rating': High/Medium/Low/Informational rating
      - 'attack_vectors': Possible attack vectors or exploitation methods
      - 'detection_signatures': Code patterns or indicators that can help detect similar issues
      
    Returns a comprehensive JSON object with these keys.
    
    Args:
        report: The vulnerability report text to analyze
        model: For OpenRouter, use an OpenRouter model ID. For Ollama, use a local model name.
    """
    # Truncate report if too long to avoid token limits
    max_report_length = 20000  # Character limit
    truncated_report = report[:max_report_length] if len(report) > max_report_length else report
    
    # Enhanced extraction prompt
    extraction_prompt = """
    Analyze this smart contract vulnerability report and extract the following information in JSON format:

    1. 'vuln_type': The precise vulnerability type, including CWE classification if available 
       (e.g., 'Reentrancy (CWE-841)'). Include sub-categories if present.

    2. 'severity_rating': The severity rating (Critical/High/Medium/Low/Informational).

    3. 'questions': 3-5 key questions that security researchers would ask when investigating this vulnerability.

    4. 'vulnerable_code': The most representative code snippet showing the vulnerability. 
       Include full function context when possible.

    5. 'fixed_code': The code snippet showing how the vulnerability was fixed.

    6. 'researcher_insights': A detailed summary of the security researcher's analysis, including:
       - Root cause of the vulnerability
       - Exploitation conditions
       - Potential impact

    7. 'attack_vectors': Specific methods an attacker could use to exploit this vulnerability.

    8. 'detection_signatures': Code patterns, function signatures, or indicators that could help
       detect similar vulnerabilities in other contracts.

    9. 'pattern': A regular expression or code pattern that could help identify this vulnerability in other code.

    If you cannot find information for a specific field, use an empty string or list as appropriate.
    Format your answer as a valid JSON object with the keys listed above.
    Do not include any explanatory text outside the JSON object.
    """
    
    # Generate a cache key based on the report content and prompt
    hasher = hashlib.md5()
    hasher.update((extraction_prompt + truncated_report).encode('utf-8'))
    cache_key = hasher.hexdigest()
    
    # Check if we have a cached response
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            console.print("[dim]Using cached analysis result[/dim]")
            return cached_data
        except (json.JSONDecodeError, IOError) as e:
            console.print(f"[yellow]Cache read error: {e}, generating new analysis[/yellow]")
    
    # Determine which API to use based on configuration and availability
    use_openrouter = False
    
    if USE_API == "auto" or USE_API == "openrouter":
        if OPENROUTER_API_KEY:
            use_openrouter = True
            # If in auto mode and OpenRouter fails, we'll fall back to Ollama
            use_fallback = (USE_API == "auto")
        else:
            if USE_API == "openrouter":
                console.print("[yellow]OPENROUTER_API_KEY not found but USE_API=openrouter, please set the API key[/yellow]")
            console.print("[dim]Falling back to local Ollama API[/dim]")
    
    if use_openrouter:
        try:
            console.print(f"[cyan]Attempting OpenRouter API with model: {DEFAULT_MODEL}[/cyan]")
            result = _generate_with_openrouter(extraction_prompt, truncated_report, DEFAULT_MODEL, cache_key)
            return result
        except Exception as e:
            if use_fallback:
                console.print(f"[yellow]OpenRouter API failed: {str(e)}[/yellow]")
                console.print(f"[cyan]Falling back to local Ollama API with model: {model}[/cyan]")
            else:
                console.print(f"[red]OpenRouter API error: {str(e)} and no fallback is enabled[/red]")
                raise
    
    # If we get here, either OpenRouter failed with fallback enabled, or we're using Ollama directly
    return _generate_with_ollama(extraction_prompt, truncated_report, model, cache_key)

def _generate_with_openrouter(extraction_prompt, report, model, cache_key):
    """Generate structured analysis using OpenRouter API"""
    # Create cache directory if it doesn't exist
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, exist_ok=True)
        
    # Define cache file path
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    
    # Check if we have a cached result
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_result = json.load(f)
            console.print(f"[green]Using cached analysis result[/green]")
            return cached_result
        except Exception as e:
            console.print(f"[yellow]Error reading cache: {e}. Will regenerate.[/yellow]")
    
    # Standard headers for OpenRouter API exactly as in DeepCurrent_v3.1.py
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/pxng0lin/DeepCurrent",  # Required for data policies
        "X-Title": "DeepCurrent Security Analysis",  # Name of your app
        "X-Data-Usage": OPENROUTER_DATA_USAGE  # Control data usage policy
    }
    
    # Prepare messages array for OpenRouter API with enhanced system prompt
    messages = [
        {"role": "system", "content": "You are an expert in smart contract security analysis. Respond with properly formatted JSON that matches the requested schema exactly."}, 
        {"role": "user", "content": extraction_prompt + "\n" + report}
    ]
    
    # Include all models to try in order of preference
    models_to_try = [model] + [m for m in BACKUP_MODELS if m != model]
    console.print(f"[cyan]Using OpenRouter API with model: {model}[/cyan]")
    
    # Try up to 3 times with different models
    max_retries = 3
    base_wait = 2  # seconds
    
    for attempt in range(max_retries):
        # Rotate through models if needed
        current_model = models_to_try[min(attempt, len(models_to_try) - 1)]
        
        try:
            console.print(f"[dim]Attempt {attempt+1}/{max_retries} with model {current_model}...[/dim]")
            
            # Request format for OpenRouter API
            payload = {
                "model": current_model,
                "messages": messages,
                "temperature": 0.2,  # Lower temperature for more deterministic output
                "max_tokens": 20000
            }
            
            # Make the API request
            response = requests.post(
                OPENROUTER_API_URL,
                headers=headers,
                json=payload,
                timeout=120
            )
            
            # Check if we hit rate limits
            if response.status_code == 429:
                console.print(f"[yellow]OpenRouter rate limit exceeded on attempt {attempt+1}[/yellow]")
                # If this isn't the last attempt and we still have models to try, continue
                if attempt < max_retries - 1 and attempt < len(models_to_try) - 1:
                    wait_time = base_wait * (2 ** attempt)
                    console.print(f"[yellow]Trying alternate model in {wait_time} seconds...[/yellow]")
                    time.sleep(wait_time)
                    continue
                else:
                    raise Exception("Rate limit exceeded for all available models")
            
            # Handle HTTP errors
            elif response.status_code != 200:
                console.print(f"[yellow]HTTP error {response.status_code} on attempt {attempt+1}[/yellow]")
                if attempt < max_retries - 1:
                    wait_time = base_wait * (2 ** attempt)
                    console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
                    time.sleep(wait_time)
                    continue
                else:
                    response.raise_for_status()
            
            # Process successful response
            try:
                result = response.json()
                
                # Log model information if available
                if "model" in result:
                    console.print(f"[dim]Using model: {result['model']}[/dim]")
                
                # Validate response structure
                if not isinstance(result, dict):
                    console.print(f"[yellow]Unexpected response type: {type(result)}[/yellow]")
                    raise ValueError(f"Unexpected response type: {type(result)}")
                    
                if "choices" not in result or not result["choices"] or not isinstance(result["choices"], list):
                    console.print(f"[yellow]Invalid response format - missing choices: {result}[/yellow]")
                    raise ValueError("Invalid API response format - missing choices")
                    
                # Extract the content from the response
                choice = result["choices"][0]
                if "message" not in choice:
                    console.print(f"[yellow]No 'message' in response choice: {choice}[/yellow]")
                    raise ValueError("No 'message' in API response")
                    
                message = choice["message"]
                if "content" not in message:
                    console.print(f"[yellow]No 'content' in message: {message}[/yellow]")
                    raise ValueError("No 'content' in API response message")
                    
                text = message["content"].strip()
                console.print(f"[dim]Response received ({len(text)} chars)[/dim]")
                
                if not text:
                    raise ValueError("Empty response from API")
                
                # Extract JSON from text if needed
                if text.startswith("{"): 
                    parsed_data = json.loads(text)
                else:
                    # Look for JSON pattern { ... }
                    json_match = re.search(r'\{[^{]*"vuln_type".*\}', text, re.DOTALL)
                    if json_match:
                        try:
                            parsed_data = json.loads(json_match.group(0))
                        except json.JSONDecodeError:
                            raise ValueError("Failed to parse JSON after multiple attempts")
                    else:
                        # Try to parse structured info from markdown-formatted response
                        console.print("[yellow]No JSON found, attempting to extract structured information from markdown...[/yellow]")
                        extracted_info = extract_structured_info_from_markdown(text)
                        if extracted_info and extracted_info["vuln_type"] != "Unknown":
                            console.print("[green]Successfully extracted structured information from markdown[/green]")
                            parsed_data = extracted_info
                        else:
                            raise ValueError("No structured information found in the response")
            except Exception as e:
                console.print(f"[yellow]Failed to parse response: {str(e)}[/yellow]")
                raise ValueError(f"Invalid API response format: {str(e)}")
                # Cache the result and ensure fields are structured correctly
                try:
                    # Ensure all expected fields exist with default values if missing
                    expected_fields = [
                        "vuln_type", "severity_rating", "questions", "vulnerable_code", 
                        "fixed_code", "researcher_insights", "attack_vectors", 
                        "detection_signatures", "pattern"
                    ]
                    
                    for field in expected_fields:
                        if field not in parsed_data:
                            if field in ["questions", "attack_vectors", "detection_signatures"]:
                                parsed_data[field] = []
                            else:
                                parsed_data[field] = ""
                    
                    # Ensure list fields are actually lists
                    list_fields = ["questions", "attack_vectors", "detection_signatures"]
                    for field in list_fields:
                        if not isinstance(parsed_data[field], list):
                            if parsed_data[field]:  # If it has a value but isn't a list
                                parsed_data[field] = [parsed_data[field]]
                            else:
                                parsed_data[field] = []
                    
                    # Cache the result
                    with open(cache_file, 'w') as f:
                        json.dump(parsed_data, f, indent=2)
                    console.print(f"[dim]Cached analysis result to {cache_file}[/dim]")
                    
                    return parsed_data
                except Exception as e:
                    console.print(f"[yellow]Failed to process or cache result: {e}[/yellow]")
                    raise ValueError(f"Failed to process response: {str(e)}")
                    
        except requests.RequestException as e:
            console.print(f"[yellow]Request error on attempt {attempt+1}: {e}[/yellow]")
        except json.JSONDecodeError as e:
            console.print(f"[yellow]JSON decode error on attempt {attempt+1}: {e}[/yellow]")
        except ValueError as e:
            console.print(f"[yellow]Value error on attempt {attempt+1}: {e}[/yellow]")
        except Exception as e:
            console.print(f"[red]Unexpected error on attempt {attempt+1}: {e}[/red]")
        
        # Don't wait after the last attempt
        if attempt < max_retries - 1:
            wait_time = base_wait * (2 ** attempt)
            console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
            time.sleep(wait_time)
    
    # If we get here, all attempts failed
    raise Exception("Failed to get a valid response from OpenRouter after multiple attempts")

def _generate_with_ollama(extraction_prompt, report, model, cache_key):
    """Generate structured analysis using local Ollama API with ollama-python client"""
    console.print(f"[cyan]Using local Ollama API with model: {model}[/cyan]")
    
    # Create cache directory if it doesn't exist
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, exist_ok=True)
        
    # Define cache file path
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    
    # Check if we have a cached result
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_result = json.load(f)
            console.print(f"[green]Using cached analysis result[/green]")
            return cached_result
        except Exception as e:
            console.print(f"[yellow]Error reading cache: {e}. Will regenerate.[/yellow]")
    
    # Try up to 3 times with exponential backoff
    max_retries = 3
    base_wait = 2  # seconds
    
    full_prompt = extraction_prompt + "\n\n" + report
    
    for attempt in range(max_retries):
        try:
            # Use the ollama-python client with chat API
            console.print(f"[dim]Attempt {attempt+1}/{max_retries} with model {model}...[/dim]")
            
            try:
                response = ollama.chat(
                    model=model,
                    messages=[
                        {
                            'role': 'system',
                            'content': 'You are a smart contract vulnerability analysis expert.'
                        },
                        {
                            'role': 'user',
                            'content': full_prompt
                        }
                    ],
                    options={
                        "temperature": 0.2,  # Lower temperature for more deterministic output
                    }
                )
                
                # Extract content from response
                if isinstance(response, dict) and 'message' in response:
                    # Dictionary format response
                    if 'content' in response['message']:
                        text = response['message']['content']
                    else:
                        raise ValueError("No content in response message")
                elif hasattr(response, 'message') and hasattr(response.message, 'content'):
                    # Object format response
                    text = response.message.content
                else:
                    raise ValueError("Unexpected response format from Ollama API")
                    
                console.print(f"[dim]Response received ({len(text)} chars)[/dim]")
                
                if not text:
                    raise ValueError("Empty response from Ollama API")
            except Exception as e:
                console.print(f"[yellow]Error with Ollama response: {str(e)}[/yellow]")
                raise
            
            # Try to extract JSON from text
            try:
                if text.startswith("{"):
                    parsed_data = json.loads(text)
                else:
                    # Try to find JSON in the response
                    json_match = re.search(r'\{[^{]*"vuln_type".*\}', text, re.DOTALL)
                    if json_match:
                        parsed_data = json.loads(json_match.group(0))
                    else:
                        # Try markdown extraction as a last resort
                        console.print("[yellow]No JSON found, attempting to extract structured information from markdown...[/yellow]")
                        extracted_info = extract_structured_info_from_markdown(text)
                        if extracted_info and extracted_info["vuln_type"] != "Unknown":
                            console.print("[green]Successfully extracted structured information from markdown[/green]")
                            parsed_data = extracted_info
                        else:
                            raise ValueError("Failed to extract structured data from response")
                
                # Ensure all expected fields exist with default values if missing
                expected_fields = [
                    "vuln_type", "severity_rating", "questions", "vulnerable_code", 
                    "fixed_code", "researcher_insights", "attack_vectors", 
                    "detection_signatures", "pattern"
                ]
                
                for field in expected_fields:
                    if field not in parsed_data:
                        if field in ["questions", "attack_vectors", "detection_signatures"]:
                            parsed_data[field] = []
                        else:
                            parsed_data[field] = ""
                
                # Ensure list fields are actually lists
                list_fields = ["questions", "attack_vectors", "detection_signatures"]
                for field in list_fields:
                    if not isinstance(parsed_data[field], list):
                        if parsed_data[field]:  # If it has a value but isn't a list
                            parsed_data[field] = [parsed_data[field]]
                        else:
                            parsed_data[field] = []
                
                # Cache the result
                with open(cache_file, 'w') as f:
                    json.dump(parsed_data, f)
                
                return parsed_data
            
            except (ValueError, json.JSONDecodeError) as e:
                console.print(f"[yellow]Failed to parse response (attempt {attempt+1}/{max_retries}): {e}[/yellow]")
        
        except requests.exceptions.RequestException as e:
            console.print(f"[yellow]API request failed (attempt {attempt+1}/{max_retries}): {e}[/yellow]")
        except Exception as e:
            console.print(f"[red]Unexpected error (attempt {attempt+1}/{max_retries}): {e}[/red]")
        
        # Don't sleep after the last attempt
        if attempt < max_retries - 1:
            wait_time = base_wait * (2 ** attempt)  # Exponential backoff
            console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
            time.sleep(wait_time)
    
    # If we get here, all attempts failed
    return {
        "vuln_type": "Unknown",
        "severity_rating": "",
        "questions": [],
        "vulnerable_code": "",
        "fixed_code": "",
        "researcher_insights": "Analysis failed due to LLM service issues.",
        "attack_vectors": [],
        "detection_signatures": [],
        "pattern": "",
        "raw_analysis": "LLM analysis failed after multiple attempts."
    }

# ---------------------- Vectorisation Functions ----------------------
def process_markdown_file(file_url: str, source: str, model_instance=None):
    """Download, embed, extract structured data via LLM, and save the report."""
    console.print(f"[bold blue]🔄 Starting vectorization for: {file_url}[/bold blue]")
    report_id = hashlib.sha256(file_url.encode("utf-8")).hexdigest()
    console.print(f"[bold yellow]🛠 Calculated Report ID: {report_id}[/bold yellow]")
    console.print(f"[bold blue]🔄 Downloading report from: {file_url}[/bold blue]")
    content = download_markdown(file_url)
    if content is None:
        console.print("[red]❌ Failed to download report. Check the URL and try again.[/red]")
        return
    console.print("[bold yellow]🔍 Extracting key information...[/bold yellow]")
    overall_embedding = compute_embedding(content, model_instance)
    sections = split_into_sections(content)
    console.print(f"[bold blue]📄 Found {len(sections)} sections in report[/bold blue]")
    section_embeddings = [
        {"title": sec["title"], "content": sec["content"], "embedding": compute_embedding(sec["content"], model_instance)}
        for sec in sections if sec["content"]
    ]
    console.print("[bold yellow]🔍 Generating structured analysis via LLM...[/bold yellow]")
    analysis_summary = generate_structured_analysis(content, model="deepseek-r1:32b")
    metadata = {
        "downloaded_at": datetime.utcnow().isoformat() + "Z",
        "report_length": len(content),
        "word_count": len(content.split()),
        "embedding_model": "all-MiniLM-L6-v2",
        "llm_model": "deepseek-r1:32b",
        "script_version": "3.2"
    }
    console.print("[bold cyan]💾 Saving data to the database...[/bold cyan]")
    save_report(report_id, source, content, overall_embedding, section_embeddings, analysis_summary, metadata)
    # Save the basic pattern extracted (if any)
    pattern = analysis_summary.get("pattern", "N/A")
    save_pattern(report_id, pattern)
    console.print("[bold green]✅ Report successfully vectorized and saved to database![/bold green]")

def process_single_file(url: str, model_instance=None):
    """Process a single Markdown file."""
    if should_ignore_file(url):
        report_id = hashlib.sha256(url.encode("utf-8")).hexdigest()
        with task_lock:
            task_status[report_id] = "Skipped (ignored file)"
        return
    process_markdown_file(url, url, model_instance)

def process_repo(url: str, model_instance=None):
    """Process all Markdown files in a GitHub repository."""
    if "github.com" not in url:
        with task_lock:
            task_status[url] = "Error: Not a GitHub URL"
        return
    parts = url.strip("/").split("/")
    if len(parts) < 5:
        with task_lock:
            task_status[url] = "Error: Invalid repo URL"
        return
    owner, repo = parts[3], parts[4]
    repo_api = f"https://api.github.com/repos/{owner}/{repo}/git/trees/main?recursive=1"
    r = requests.get(repo_api)
    if r.status_code != 200:
        with task_lock:
            task_status[url] = f"Error: Repo fetch failed (HTTP {r.status_code})"
        return
    tree = r.json().get("tree", [])
    md_files = [item["path"] for item in tree if item["path"].endswith(".md") and "readme" not in item["path"].lower()]
    if not md_files:
        with task_lock:
            task_status[url] = "No Markdown files found"
        return
    for path in md_files:
        file_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{path}"
        process_markdown_file(file_url, url + "/" + path, model_instance)

# ---------------------- Detection Library Functions ----------------------
def init_detection_library_table():
    """
    Create the detection_library table if it doesn't exist.
    Schema:
      - vuln_type (TEXT PRIMARY KEY)
      - details (JSON string with aggregated questions, examples, insights)
      - template (Robust detection template as TEXT)
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS detection_library (
            vuln_type TEXT PRIMARY KEY,
            details TEXT,
            template TEXT
        )
    ''')
    conn.commit()
    conn.close()

def extract_structured_info_from_markdown(text):
    """Extract structured vulnerability info from a markdown-formatted response."""
    # Initialize our structured result
    result = {
        "vuln_type": "Unknown",
        "severity_rating": "Unknown",
        "vulnerability_description": "",
        "questions": [],
        "vulnerable_code": "",
        "fixed_code": "",
        "researcher_insights": "",
        "attack_vectors": [],
        "detection_signatures": [],
        "pattern": ""
    }
    
    # Extract vulnerability type from header
    title_match = re.search(r'^\s*#{1,6}\s+(.+)$', text, re.MULTILINE)
    if title_match:
        result["vuln_type"] = title_match.group(1).strip()
    
    # Extract severity rating
    severity_match = re.search(r'\*\*severity\*\*\s*:\s*([^\n]+)', text, re.IGNORECASE)
    if severity_match:
        result["severity_rating"] = severity_match.group(1).strip()
    
    # Extract description (everything between severity and recommendation)
    desc_pattern = r'\*\*severity\*\*\s*:[^\n]+\n\s*([\s\S]*?)(?:\*\*recommendation|$)'    
    desc_match = re.search(desc_pattern, text, re.IGNORECASE)
    if desc_match:
        result["researcher_insights"] = desc_match.group(1).strip()
        result["vulnerability_description"] = desc_match.group(1).strip()
    else:
        # If no recommendation section, try to grab everything after severity
        desc_pattern = r'\*\*severity\*\*\s*:[^\n]+\n\s*([\s\S]*)'    
        desc_match = re.search(desc_pattern, text, re.IGNORECASE)
        if desc_match:
            result["researcher_insights"] = desc_match.group(1).strip()
            result["vulnerability_description"] = desc_match.group(1).strip()
    
    # Extract attack vectors based on context clues
    if "allowing" in result["vulnerability_description"].lower():
        attack_pattern = r'allowing ([^\.,]+)'
        attack_match = re.search(attack_pattern, result["vulnerability_description"], re.IGNORECASE)
        if attack_match:
            result["attack_vectors"].append(attack_match.group(1).strip())
    
    # Look for potential detection signatures
    if "before" in result["vulnerability_description"].lower():
        signature_pattern = r'([^\.,]+) before ([^\.,]+)'
        sig_match = re.search(signature_pattern, result["vulnerability_description"], re.IGNORECASE)
        if sig_match:
            result["detection_signatures"].append(f"Check if {sig_match.group(1).strip()} occurs before {sig_match.group(2).strip()}")
    
    # Extract recommendation as a detection signature
    rec_pattern = r'\*\*recommendation\*\*\s*:?\s*([\s\S]*)'
    rec_match = re.search(rec_pattern, text, re.IGNORECASE)
    if rec_match:
        recommendation = rec_match.group(1).strip()
        if recommendation:
            result["detection_signatures"].append(recommendation)
    
    # Add simple questions based on vulnerability type
    if result["vuln_type"] != "Unknown":
        result["questions"] = [
            f"How can the {result['vuln_type']} vulnerability be exploited?",
            f"What are the conditions needed for a {result['vuln_type']} attack?",
            f"How can the {result['vuln_type']} vulnerability be prevented?"
        ]
    
    return result

def cluster_vulnerabilities(vuln_details_list, model=DEFAULT_OLLAMA_MODEL):
    """Enhanced vulnerability clustering using advanced LLM analysis techniques"""
    if not vuln_details_list:
        return {}
    
    console.print("[bold cyan]🔍 Starting enhanced vulnerability clustering...[/bold cyan]")
    console.print(f"[bold blue]Found {len(vuln_details_list)} vulnerability reports to analyze[/bold blue]")
    
    # Extract richer vulnerability data to improve clustering accuracy
    vuln_data = []
    for i, details in enumerate(vuln_details_list):
        if not details.get("vuln_type"):
            continue
            
        vuln_entry = {
            "index": i,
            "vuln_type": details.get("vuln_type", "Unknown"),
            "severity": details.get("severity_rating", ""),
        }
        
        # Add detection signatures if available
        if "detection_signatures" in details and details["detection_signatures"]:
            if isinstance(details["detection_signatures"], list):
                vuln_entry["signatures"] = details["detection_signatures"][:2]
            else:
                vuln_entry["signatures"] = [str(details["detection_signatures"])]
        
        # Add attack vectors if available
        if "attack_vectors" in details and details["attack_vectors"]:
            if isinstance(details["attack_vectors"], list):
                vuln_entry["attack_vectors"] = details["attack_vectors"][:2]
            else:
                vuln_entry["attack_vectors"] = [str(details["attack_vectors"])]
                
        # Include code snippet info (just presence, not full content to save tokens)
        vuln_entry["has_code_examples"] = bool(details.get("vulnerable_code") or details.get("fixed_code"))
        
        vuln_data.append(vuln_entry)
    
    # If we have very few vulnerabilities, skip complex clustering
    if len(vuln_data) < 3:
        console.print("[yellow]Few vulnerabilities found. Using simple categorization.[/yellow]")
        library = {}
        for details in vuln_details_list:
            vuln_type = details.get("vuln_type", "Unknown")
            if not vuln_type or vuln_type == "Unknown":
                continue
                
            if vuln_type not in library:
                library[vuln_type] = {
                    "questions": [], 
                    "vulnerable_examples": [], 
                    "fixed_examples": [],
                    "insights": [], 
                    "patterns": [], 
                    "attack_vectors": [], 
                    "severity_ratings": [],
                    "detection_signatures": []
                }
            
            # Add all details to the library
            _update_library_with_details(library[vuln_type], details)
            
        return library
    
    # Enhanced clustering prompt that aligns with DeepCurrent's detection system
    prompt = """
    You are a smart contract security expert. Analyze these vulnerability types and organize them into a comprehensive detection library.
    Examine each vulnerability carefully and determine the logical categories that would be most useful for detection and scanning purposes.
    
    CLUSTERING RULES:
    1. Use precise, actionable categories (e.g., "Reentrancy (CWE-841)" instead of just "Logic Error")
    2. Include CWE identifiers when applicable
    3. Merge near-identical vulnerabilities even if they have different names
    4. Keep truly distinct vulnerabilities separate, even if they fall in the same general area
    5. Prioritize categories that will be most useful for automated vulnerability detection
    6. Consider severity levels when creating categories
    
    VULNERABILITY DATA:
    {}
    
    OUTPUT INSTRUCTIONS:
    Return a JSON object where:
    - Each key is a standardized, precise vulnerability category name (with CWE if possible)
    - Each value is an array of indices from the input list that belong to this category
    
    Example format:
    {{
      "Reentrancy (CWE-841)": [0, 3, 7],
      "Integer Overflow (CWE-190)": [1, 4],
      "Access Control Issues (CWE-284)": [2, 5, 6]
    }}
    
    Only provide the JSON with no additional explanation.
    """.format(json.dumps(vuln_data, indent=2))
    
    # Use multiple attempts with exponential backoff
    max_retries = 3
    base_wait = 2  # seconds
    
    for attempt in range(max_retries):
        try:
            # Create a cache directory if it doesn't exist
            if not os.path.exists(CACHE_DIR):
                os.makedirs(CACHE_DIR, exist_ok=True)
                
            # Generate cache key for this clustering operation
            hasher = hashlib.md5()
            hasher.update(prompt.encode('utf-8'))
            cache_key = hasher.hexdigest()
            cache_file = os.path.join(CACHE_DIR, f"cluster_{cache_key}.json")
            
            # Check if we have a cached result
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, 'r') as f:
                        cached_result = json.load(f)
                    console.print(f"[green]Using cached clustering result[/green]")
                    return cached_result
                except Exception as e:
                    console.print(f"[yellow]Error reading cache: {e}. Will regenerate.[/yellow]")
            
            # Determine which API to use based on configuration
            use_openrouter = False
            if USE_API == "auto" or USE_API == "openrouter":
                if OPENROUTER_API_KEY:
                    use_openrouter = True
            
            if use_openrouter:
                # Use OpenRouter API
                console.print(f"[cyan]Attempt {attempt+1}/{max_retries}: Clustering vulnerabilities using OpenRouter...[/cyan]")
                try:
                    headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                        "HTTP-Referer": "https://github.com/pxng0lin/DeepCurrent",
                        "X-Title": "DeepCurrent Security Analysis"
                    }
                    
                    messages = [
                        {"role": "system", "content": "You are a smart contract security expert. Analyze vulnerability types and organize them into comprehensive categories."}, 
                        {"role": "user", "content": prompt}
                    ]
                    
                    payload = {
                        "model": DEFAULT_MODEL,
                        "messages": messages,
                        "temperature": 0.2,
                        "max_tokens": 20000
                    }
                    
                    response = requests.post(
                        "https://openrouter.ai/api/v1/chat/completions",
                        headers=headers,
                        json=payload,
                        timeout=180
                    )
                except Exception as e:
                    console.print(f"[yellow]OpenRouter API error: {e}. Falling back to Ollama...[/yellow]")
                    use_openrouter = False
            
            if not use_openrouter:
                # Use Ollama API
                console.print(f"[cyan]Attempt {attempt+1}/{max_retries}: Clustering vulnerabilities using Ollama...[/cyan]")
                headers = {"Content-Type": "application/json"}
                payload = {
                    "model": model,
                    "prompt": prompt,
                    "temperature": 0.2,  # Lower temperature for more consistent results
                    "max_tokens": 20000
                }
                
                response = requests.post(LLM_API_URL, json=payload, headers=headers, timeout=120)
            
            if response.status_code != 200:
                console.print(f"[yellow]HTTP error {response.status_code}. Retrying...[/yellow]")
                if attempt < max_retries - 1:
                    wait_time = base_wait * (2 ** attempt)
                    time.sleep(wait_time)
                continue
                
            result = response.json()
            
            # Handle different response formats based on API used
            if use_openrouter:
                if "choices" in result and result["choices"] and len(result["choices"]) > 0:
                    if "message" in result["choices"][0] and "content" in result["choices"][0]["message"]:
                        result_text = result["choices"][0]["message"]["content"].strip()
                    else:
                        console.print("[yellow]Invalid OpenRouter response structure. Retrying...[/yellow]")
                        if attempt < max_retries - 1:
                            wait_time = base_wait * (2 ** attempt)
                            time.sleep(wait_time)
                        continue
                else:
                    console.print("[yellow]Invalid OpenRouter response structure. Retrying...[/yellow]")
                    if attempt < max_retries - 1:
                        wait_time = base_wait * (2 ** attempt)
                        time.sleep(wait_time)
                    continue
            else:  # Ollama response format
                if "choices" in result and result["choices"]:
                    result_text = result["choices"][0].get("text", "").strip()
                elif "response" in result:
                    result_text = result["response"].strip()
                else:
                    console.print("[yellow]Invalid Ollama response structure. Retrying...[/yellow]")
                    if attempt < max_retries - 1:
                        wait_time = base_wait * (2 ** attempt)
                        time.sleep(wait_time)
                    continue
            if not result_text:
                console.print("[yellow]Empty response. Retrying...[/yellow]")
                if attempt < max_retries - 1:
                    wait_time = base_wait * (2 ** attempt)
                    time.sleep(wait_time)
                continue
            
            # Process and clean the response
            # Remove code fences if present
            if result_text.startswith("```") and result_text.endswith("```"):
                result_text = "\n".join(result_text.split("\n")[1:-1])
            elif result_text.startswith("```"):
                result_text = "\n".join(result_text.split("\n")[1:])
                
            # Remove any JSON syntax identifier
            if result_text.startswith("json"):
                result_text = result_text[4:].lstrip()
                
            # Clean up any trailing commas before closing brackets
            result_text = re.sub(r",\s*([\]}])", r"\1", result_text)
            
            # Extract JSON if embedded in other text
            if not result_text.startswith("{"):
                json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
                if json_match:
                    result_text = json_match.group(0)
            
            # Parse the clustering result
            try:
                # Use raw_decode to handle potential trailing data
                decoder = json.JSONDecoder()
                clustering, idx = decoder.raw_decode(result_text)
                
                if not isinstance(clustering, dict):
                    raise ValueError("Clustering result is not a dictionary")
                    
                # Success - create the library based on clustering
                library = {}
                
                # Initialize categories with extended fields
                for category in clustering.keys():
                    library[category] = {
                        "questions": [], 
                        "vulnerable_examples": [], 
                        "fixed_examples": [],
                        "insights": [], 
                        "patterns": [], 
                        "attack_vectors": [], 
                        "severity_ratings": [],
                        "detection_signatures": []
                    }
                
                # Populate library based on clustering
                for category, indices in clustering.items():
                    for idx in indices:
                        if isinstance(idx, int) and 0 <= idx < len(vuln_details_list):
                            details = vuln_details_list[idx]
                            _update_library_with_details(library[category], details)
                
                # Remove duplicates and limit entries
                for category_data in library.values():
                    _deduplicate_library_category(category_data)
                
                console.print(f"[green]✅ Successfully clustered into {len(library)} vulnerability categories[/green]")
                
                # Cache the successful result
                try:
                    with open(cache_file, 'w') as f:
                        json.dump(library, f)
                except Exception as e:
                    console.print(f"[yellow]Failed to cache result: {e}[/yellow]")
                    
                return library
                
            except (ValueError, json.JSONDecodeError) as e:
                console.print(f"[yellow]Failed to parse clustering result: {e}[/yellow]")
                if attempt < max_retries - 1:
                    wait_time = base_wait * (2 ** attempt)
                    time.sleep(wait_time)
                continue
                
        except requests.exceptions.RequestException as e:
            console.print(f"[yellow]Request error: {e}[/yellow]")
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
        
        if attempt < max_retries - 1:
            wait_time = base_wait * (2 ** attempt)
            console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
            time.sleep(wait_time)
    
    # If all attempts failed, fall back to simple categorization
    console.print("[yellow]Clustering failed. Falling back to simple categorization by vulnerability type.[/yellow]")
    library = {}
    for details in vuln_details_list:
        vuln_type = details.get("vuln_type", "Unknown")
        if not vuln_type or vuln_type == "Unknown":
            continue
            
        if vuln_type not in library:
            library[vuln_type] = {
                "questions": [], 
                "vulnerable_examples": [], 
                "fixed_examples": [],
                "insights": [], 
                "patterns": [], 
                "attack_vectors": [], 
                "severity_ratings": [],
                "detection_signatures": []
            }
        
        # Add all details to the library
        _update_library_with_details(library[vuln_type], details)
    
    # Deduplicate the simple categorization results
    for category_data in library.values():
        _deduplicate_library_category(category_data)
        
    return library

def _update_library_with_details(category_data, details):
    """Helper function to update a category with vulnerability details"""
    # Add standard fields
    if details.get("questions"):
        if isinstance(details["questions"], list):
            category_data["questions"].extend(details["questions"])
        else:
            category_data["questions"].append(str(details["questions"]))
    
    if details.get("vulnerable_code"):
        category_data["vulnerable_examples"].append(details["vulnerable_code"])
    
    if details.get("fixed_code"):
        category_data["fixed_examples"].append(details["fixed_code"])
    
    if details.get("researcher_insights"):
        category_data["insights"].append(details["researcher_insights"])
    
    if details.get("pattern"):
        category_data["patterns"].append(details["pattern"])
    
    # Add enhanced fields
    if details.get("attack_vectors"):
        if isinstance(details["attack_vectors"], list):
            category_data["attack_vectors"].extend(details["attack_vectors"])
        else:
            category_data["attack_vectors"].append(str(details["attack_vectors"]))
    
    if details.get("severity_rating"):
        category_data["severity_ratings"].append(details["severity_rating"])
    
    if details.get("detection_signatures"):
        if isinstance(details["detection_signatures"], list):
            category_data["detection_signatures"].extend(details["detection_signatures"])
        else:
            category_data["detection_signatures"].append(str(details["detection_signatures"]))

def _deduplicate_library_category(category_data):
    """Helper function to deduplicate entries in a category and limit their number"""
    # Remove duplicates using sets where appropriate
    if category_data["questions"]:
        category_data["questions"] = list(set(category_data["questions"]))[:5]  # Limit to 5
        
    if category_data["attack_vectors"]:
        category_data["attack_vectors"] = list(set(category_data["attack_vectors"]))[:5]  # Limit to 5
        
    if category_data["detection_signatures"]:
        category_data["detection_signatures"] = list(set(category_data["detection_signatures"]))[:5]  # Limit to 5
        
    if category_data["patterns"]:
        category_data["patterns"] = list(set(category_data["patterns"]))[:5]  # Limit to 5
        
    # Limit examples and insights
    category_data["vulnerable_examples"] = category_data["vulnerable_examples"][:3]  # Limit to 3
    category_data["fixed_examples"] = category_data["fixed_examples"][:3]  # Limit to 3
    category_data["insights"] = category_data["insights"][:3]  # Limit to 3
  
def format_examples(examples):
    """Convert a list of examples (which may be dicts) into a formatted string."""
    formatted = []
    for ex in examples:
        if isinstance(ex, dict):
            formatted.append(json.dumps(ex, indent=2))
        else:
            formatted.append(str(ex))
    return "\n".join(formatted)

def display_detection_library(library):
    """
    Display a summary table of the detection pattern library (the aggregated in-memory structure).
    If the aggregated details for a vulnerability type is a list, use the first element.
    Convert dict entries into formatted strings.
    """
    table = Table(title="Detection Pattern Library (Aggregated in Memory)")
    table.add_column("Vulnerability Type", style="cyan")
    table.add_column("Questions", style="magenta")
    table.add_column("Vulnerable Examples", style="red")
    table.add_column("Fixed Examples", style="green")
    
    for vuln_type, details in library.items():
        # If details is a list, use the first element (if available)
        if isinstance(details, list):
            details = details[0] if details else {}
        questions = "\n".join(details.get("questions", []))
        vuln_examples = format_examples(details.get("vulnerable_examples", []))
        fixed_examples = format_examples(details.get("fixed_examples", []))
        table.add_row(vuln_type, questions, vuln_examples, fixed_examples)
    console.print(table)

def build_detection_library(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT analysis_summary FROM reports")
    rows = c.fetchall()
    conn.close()
    
    vuln_details_list = []
    for (analysis_summary,) in rows:
        try:
            details = json.loads(analysis_summary)
            vuln_details_list.append(details)
        except Exception:
            continue

    # Use LLM to cluster the vulnerabilities into categories.
    library = cluster_vulnerabilities(vuln_details_list)
    # If library is a string, try to parse it
    if isinstance(library, str):
        try:
            library = json.loads(library)
        except Exception as e:
            console.print(f"[red]Failed to parse detection library string: {e}[/red]")
            library = {}
    return library

def generate_robust_detection_template(vuln_type, details, model=DEFAULT_OLLAMA_MODEL):
    """
    Generate a detailed, actionable detection template for a vulnerability type
    using the enhanced library structure with severity, attack vectors, and detection signatures.
    
    Args:
        vuln_type: The type of vulnerability to generate a template for
        details: Dictionary containing vulnerability details
        model: For OpenRouter, use an OpenRouter model ID. For Ollama, use a local model name.
    """
    # Extract key components that could help improve the template
    questions = details.get("questions", [])
    vulnerabilities = details.get("vulnerable_examples", [])
    fixes = details.get("fixed_examples", [])
    insights = details.get("insights", [])
    patterns = details.get("patterns", [])
    attack_vectors = details.get("attack_vectors", [])
    severity_ratings = details.get("severity_ratings", [])
    detection_signatures = details.get("detection_signatures", [])
    
    # Determine overall severity if available
    severity = "Unknown"
    if severity_ratings:
        # Try to extract numerical values
        numeric_values = []
        for rating in severity_ratings:
            # Try to extract a number like "7.5" or "8/10"
            matches = re.findall(r'\b(\d+(?:\.\d+)?)(?:/10)?\b', rating.lower())
            if matches:
                try:
                    numeric_values.append(float(matches[0]))
                except ValueError:
                    pass
            # Look for common severity terms
            elif "critical" in rating.lower() or "high" in rating.lower():
                numeric_values.append(8.0)
            elif "medium" in rating.lower():
                numeric_values.append(5.0)
            elif "low" in rating.lower():
                numeric_values.append(3.0)
        
        # Calculate average severity if we found numeric values
        if numeric_values:
            avg_severity = sum(numeric_values) / len(numeric_values)
            # Map to severity category
            if avg_severity >= 7.0:
                severity = "Critical"
            elif avg_severity >= 5.0:
                severity = "High"
            elif avg_severity >= 3.0:
                severity = "Medium"
            else:
                severity = "Low"
    
    # Build a prompt that directs the LLM to generate a comprehensive template
    prompt = f"""
    You are a smart contract security expert creating a detection template for '{vuln_type}'.
    
    VULNERABILITY INFORMATION:
    - Overall Severity: {severity}
    - Attack Vectors: {', '.join(attack_vectors) if attack_vectors else 'Not specified'}
    
    DETECTION CRITERIA:
    Questions: {json.dumps(questions)}
    Detection Signatures: {json.dumps(detection_signatures)}
    Patterns: {json.dumps(patterns)}
    
    CODE EXAMPLES:
    Vulnerable Code: {json.dumps(vulnerabilities[:1]) if vulnerabilities else 'Not available'}
    Fixed Code: {json.dumps(fixes[:1]) if fixes else 'Not available'}
    
    RESEARCHER INSIGHTS:
    {json.dumps(insights) if insights else 'Not available'}
    
    INSTRUCTIONS:
    Create a comprehensive detection template that includes:
    1. Clear title and description of the vulnerability
    2. Severity rating and impact assessment
    3. Technical detection methodology with specific code patterns to look for
    4. Required security checks and questions to ask
    5. Example vulnerable and fixed code (if available)
    6. Prevention strategies
    
    Format the template as a structured document with clear sections.
    Use Markdown formatting for better readability.
    """
    
    # Generate a cache key based on the content and prompt
    hasher = hashlib.md5()
    hasher.update((prompt + str(vuln_type)).encode('utf-8'))
    cache_key = hasher.hexdigest()
    
    # Check if we have a cached response
    cache_file = os.path.join(CACHE_DIR, f"template_{cache_key}.md")
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_template = f.read()
            console.print("[dim]Using cached template[/dim]")
            return cached_template
        except IOError as e:
            console.print(f"[yellow]Cache read error: {e}, generating new template[/yellow]")
    
    # Determine which API to use based on configuration and availability
    use_openrouter = False
    
    if USE_API == "auto" or USE_API == "openrouter":
        if OPENROUTER_API_KEY:
            use_openrouter = True
            # If in auto mode and OpenRouter fails, we'll fall back to Ollama
            use_fallback = (USE_API == "auto")
        else:
            if USE_API == "openrouter":
                console.print("[yellow]OPENROUTER_API_KEY not found but USE_API=openrouter, please set the API key[/yellow]")
            console.print("[dim]Falling back to local Ollama API[/dim]")
    
    template = None
    
    if use_openrouter:
        try:
            template = _generate_template_with_openrouter(prompt, vuln_type, DEFAULT_MODEL)
        except Exception as e:
            if use_fallback:
                console.print(f"[yellow]OpenRouter API failed: {e}, falling back to Ollama[/yellow]")
            else:
                raise
    
    # If template is None, either OpenRouter failed with fallback enabled, or we're using Ollama directly
    if template is None:
        template = _generate_template_with_ollama(prompt, vuln_type, model)
    
    # Cache the result
    try:
        with open(cache_file, 'w') as f:
            f.write(template)
    except IOError as e:
        console.print(f"[yellow]Failed to cache template: {e}[/yellow]")
    
    return template

def _generate_template_with_openrouter(prompt, vuln_type, model):
    """Generate template using OpenRouter API"""
    global OPENROUTER_API_KEY
    
    # Create cache directory if it doesn't exist
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, exist_ok=True)
    
    # Generate a unique cache key for this template request
    hasher = hashlib.md5()
    hasher.update((prompt + vuln_type + model).encode('utf-8'))
    cache_key = hasher.hexdigest()
    cache_file = os.path.join(CACHE_DIR, f"or_template_{cache_key}.md")
    
    # Check if we have a cached result
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_template = f.read()
            console.print(f"[green]Using cached template for {vuln_type}[/green]")
            return cached_template
        except Exception as e:
            console.print(f"[yellow]Error reading cache: {e}. Will regenerate.[/yellow]")
    
    # Standard headers for OpenRouter API exactly as in DeepCurrent_v3.1.py
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/pxng0lin/DeepCurrent",  # Required for data policies
        "X-Title": "DeepCurrent Security Analysis",  # Name of your app
        "X-Data-Usage": OPENROUTER_DATA_USAGE  # Control data usage policy
    }
    
    # Prepare messages array for OpenRouter API
    messages = [
        {"role": "system", "content": "You are an expert in smart contract security analysis specializing in creating detailed vulnerability detection templates."},
        {"role": "user", "content": prompt}
    ]
    
    # Include all models to try in order of preference
    models_to_try = [model] + [m for m in BACKUP_MODELS if m != model]
    console.print(f"[cyan]Using OpenRouter API with model: {model}[/cyan]")
    
    # Try up to 3 times with different models
    max_retries = 3
    base_wait = 2  # seconds
    
    for attempt in range(max_retries):
        # Rotate through models if needed
        current_model = models_to_try[min(attempt, len(models_to_try) - 1)]
        
        try:
            console.print(f"[dim]Attempt {attempt+1}/{max_retries} with model {current_model}...[/dim]")
            
            payload = {
                "model": current_model,
                "messages": messages,
                "temperature": 0.3,  # Lower temperature for consistent template output
                "max_tokens": 20000
            }
            
            # Make the API request
            response = requests.post(
                OPENROUTER_API_URL,
                headers=headers,
                json=payload,
                timeout=120
            )
            
            # Handle rate limits and other HTTP errors
            if response.status_code == 429:
                console.print(f"[yellow]OpenRouter rate limit exceeded on attempt {attempt+1}[/yellow]")
                
                # Try rotating API key if available
                # Session-based implementation doesn't support key rotation
                console.print(f"[yellow]Rate limit reached. You may need to update your API key.[/yellow]")
                
                # If we can try another model instead
                if attempt < max_retries - 1 and attempt < len(models_to_try) - 1:
                    wait_time = base_wait * (2 ** attempt)
                    console.print(f"[yellow]Trying alternate model in {wait_time} seconds...[/yellow]")
                    time.sleep(wait_time)
                    continue
                else:
                    raise Exception("Rate limit exceeded for all available models/keys")
            elif response.status_code != 200:
                console.print(f"[yellow]HTTP error {response.status_code} on attempt {attempt+1}[/yellow]")
                if attempt < max_retries - 1:
                    wait_time = base_wait * (2 ** attempt)
                    console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
                    time.sleep(wait_time)
                    continue
                else:
                    response.raise_for_status()
            
            # Process successful response
            try:
                result = response.json()
                
                # Log model information if available
                if "model" in result:
                    console.print(f"[dim]Using model: {result['model']}[/dim]")
                
                # Validate response structure
                if not isinstance(result, dict):
                    console.print(f"[yellow]Unexpected response type: {type(result)}[/yellow]")
                    raise ValueError(f"Unexpected response type: {type(result)}")
                    
                if "choices" not in result or not result["choices"] or not isinstance(result["choices"], list):
                    console.print(f"[yellow]Invalid response format - missing choices: {result}[/yellow]")
                    raise ValueError("Invalid API response format - missing choices")
                    
                # Extract the content from the response
                choice = result["choices"][0]
                if "message" not in choice:
                    console.print(f"[yellow]No 'message' in response choice: {choice}[/yellow]")
                    raise ValueError("No 'message' in API response")
                    
                message = choice["message"]
                if "content" not in message:
                    console.print(f"[yellow]No 'content' in message: {message}[/yellow]")
                    raise ValueError("No 'content' in API response message")
                    
                template = message["content"].strip()
                console.print(f"[dim]Template received ({len(template)} chars)[/dim]")
                
                if not template:
                    raise ValueError("Empty template from API")
                
                # Cache the successful response
                try:
                    with open(cache_file, 'w') as f:
                        f.write(template)
                    console.print(f"[dim]Cached template to {cache_file}[/dim]")
                except Exception as e:
                    console.print(f"[yellow]Failed to cache template: {e}[/yellow]")
                
                return template
            except Exception as e:
                console.print(f"[yellow]Failed to parse template response: {str(e)}[/yellow]")
                raise ValueError(f"Invalid template API response format: {str(e)}")
            
        except Exception as e:
            console.print(f"[yellow]Error on attempt {attempt+1}: {e}[/yellow]")
        
        # Don't wait after the last attempt
        if attempt < max_retries - 1:
            wait_time = base_wait * (2 ** attempt)
            console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
            time.sleep(wait_time)
    
    # All attempts failed
    return None

def _generate_template_with_ollama(prompt, vuln_type, model):
    """Generate template using local Ollama API with ollama-python client"""
    console.print(f"[cyan]Using local Ollama API with model: {model}[/cyan]")
    
    # Create cache directory if it doesn't exist
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, exist_ok=True)
        
    # Generate a unique cache key for this template request
    hasher = hashlib.md5()
    hasher.update((prompt + vuln_type + model).encode('utf-8'))
    cache_key = hasher.hexdigest()
    cache_file = os.path.join(CACHE_DIR, f"ollama_template_{cache_key}.md")
    
    # Check if we have a cached result
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_template = f.read()
            console.print(f"[green]Using cached template for {vuln_type}[/green]")
            return cached_template
        except Exception as e:
            console.print(f"[yellow]Error reading cache: {e}. Will regenerate.[/yellow]")
            
    # Try up to 3 times with exponential backoff
    max_retries = 3
    base_wait = 2  # seconds
    
    for attempt in range(max_retries):
        try:
            # Use the ollama-python client with chat API
            console.print(f"[dim]Attempt {attempt+1}/{max_retries} with model {model}...[/dim]")
            
            response = ollama.chat(
                model=model,
                messages=[
                    {
                        'role': 'system',
                        'content': 'You are a smart contract security expert specializing in creating detailed vulnerability detection templates.'
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                options={
                    "temperature": 0.3,  # Lower temperature for more consistent, focused results
                }
            )
            
            # Extract content from response
            template = ""
            if isinstance(response, dict) and 'message' in response:
                # Dictionary format response
                if 'content' in response['message']:
                    template = response['message']['content']
                else:
                    raise ValueError("No content in response message")
            elif hasattr(response, 'message') and hasattr(response.message, 'content'):
                # Object format response
                template = response.message.content
            else:
                raise ValueError("Unexpected response format from Ollama API")
                
            console.print(f"[dim]Template received ({len(template)} chars)[/dim]")
            
            if not template:
                raise ValueError("Empty template response")
                
            # Cache the successful result
            try:
                with open(cache_file, 'w') as f:
                    f.write(template)
            except Exception as e:
                console.print(f"[yellow]Failed to cache template: {e}[/yellow]")
                
            return template
                
        except requests.exceptions.RequestException as e:
            console.print(f"[yellow]Request error on attempt {attempt+1}: {e}[/yellow]")
        except ValueError as e:
            console.print(f"[yellow]Value error on attempt {attempt+1}: {e}[/yellow]")
        except Exception as e:
            console.print(f"[red]Unexpected error on attempt {attempt+1}: {e}[/red]")
            
        # Don't wait after the last attempt
        if attempt < max_retries - 1:
            wait_time = base_wait * (2 ** attempt)
            console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
            time.sleep(wait_time)
    
    # Fallback template if all attempts fail
    return f"""
    # {vuln_type} - Detection Template
    
    ## Description
    This vulnerability represents a security issue in smart contracts. Due to technical issues, 
    a complete template could not be generated. Please refer to the vulnerability details for more information.
    
    ## Available Information
    - Questions to ask: {len(questions) if 'questions' in details else 0} questions available
    - Code examples: {len(vulnerabilities)} vulnerable examples, {len(fixes)} fixed examples
    - Known patterns: {len(patterns)} patterns identified
    
    ## Manual Review Required
    Please conduct a manual review of this vulnerability type using the provided details.
    """

def save_detection_library_to_db(library, db_path=DB_PATH):
    """
    Save the aggregated detection library and robust detection templates into the detection_library table.
    For each vulnerability category, call the LLM to generate a robust template.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    for vuln_type, details in library.items():
        robust_template = generate_robust_detection_template(vuln_type, details)
        details_json = json.dumps(details, indent=4)
        c.execute('''
            INSERT OR REPLACE INTO detection_library (vuln_type, details, template)
            VALUES (?, ?, ?)
        ''', (vuln_type, details_json, robust_template))
    conn.commit()
    conn.close()
    console.print("[green]Detection library and robust templates have been saved to the database.[/green]")

def view_detection_library():
    """
    Query the detection_library table and display its contents in a table.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT vuln_type, template FROM detection_library")
    rows = c.fetchall()
    conn.close()
    if not rows:
        console.print("[yellow]No detection library entries found.[/yellow]")
        return
    table = Table(title="Detection Library Contents", show_lines=True)
    table.add_column("Vulnerability Type", style="cyan")
    table.add_column("Robust Detection Template", style="white")
    for row in rows:
        vuln_type, template = row
        # Truncate template display if needed
        template_display = template if len(template) <= 300 else template[:300] + "..."
        table.add_row(vuln_type, template_display)
    console.print(table)

def display_detection_library(library):
    """Display an enhanced view of the detection library with all available fields"""
    # If library is a string, attempt to convert it
    if isinstance(library, str):
        try:
            library = json.loads(library)
        except Exception as e:
            console.print(f"[red]Failed to convert library string: {e}[/red]")
            return
    
    # Check if library is empty
    if not library:
        console.print("[yellow]Detection library is empty. No vulnerability patterns to display.[/yellow]")
        return
        
    # Print a summary header
    console.print(f"\n[bold cyan]📚 Detection Library Summary[/bold cyan]")
    console.print(f"[blue]Found {len(library)} vulnerability categories in the library[/blue]")
    
    # Create an expanded table with all the enhanced fields
    table = Table(title="Enhanced Detection Pattern Library", show_lines=True, box=box.ROUNDED)
    
    # Add all columns including new ones
    table.add_column("Vulnerability Type", style="cyan", no_wrap=True)
    table.add_column("Severity", style="yellow", justify="center")
    table.add_column("Detection Signatures", style="bright_magenta", max_width=30)
    table.add_column("Attack Vectors", style="red", max_width=30)
    table.add_column("Examples", style="green", max_width=30)
    
    # Process each vulnerability type
    for vuln_type, details in library.items():
        # Ensure details is a dictionary
        if not isinstance(details, dict):
            try:
                details = dict(details) if details else {}
            except Exception:
                details = {}
        
        # Calculate severity
        severity_ratings = details.get("severity_ratings", [])
        severity = "Unknown"
        
        if severity_ratings:
            # Extract severity values using similar logic as the template generator
            severity_values = []
            for rating in severity_ratings:
                rating_str = str(rating).lower()
                if "critical" in rating_str:
                    severity_values.append("Critical")
                elif "high" in rating_str:
                    severity_values.append("High")
                elif "medium" in rating_str:
                    severity_values.append("Medium")
                elif "low" in rating_str:
                    severity_values.append("Low")
            
            # Use most common severity if available
            if severity_values:
                from collections import Counter
                severity_counter = Counter(severity_values)
                severity = severity_counter.most_common(1)[0][0]
        
        # Format detection signatures
        detection_signatures = details.get("detection_signatures", [])
        signatures_text = "\n".join([f"• {sig[:100]}..." if len(sig) > 100 else f"• {sig}" for sig in detection_signatures[:3]]) if detection_signatures else "None specified"
        
        # Format attack vectors
        attack_vectors = details.get("attack_vectors", [])
        vectors_text = "\n".join([f"• {vec[:100]}..." if len(vec) > 100 else f"• {vec}" for vec in attack_vectors[:3]]) if attack_vectors else "None specified"
        
        # Format code examples (combine vulnerable and fixed)
        vuln_examples = details.get("vulnerable_examples", [])
        fixed_examples = details.get("fixed_examples", [])
        
        if vuln_examples or fixed_examples:
            examples_text = f"[bold]Found:[/bold] {len(vuln_examples)} vulnerable examples\n[bold]Fixed:[/bold] {len(fixed_examples)} fixed examples"
            
            # Add snippet of first example if available
            if vuln_examples:
                first_example = str(vuln_examples[0])
                if len(first_example) > 100:
                    examples_text += f"\n\n[dim]Sample: {first_example[:100]}...[/dim]"
        else:
            examples_text = "No code examples available"
        
        # Add the row to the table
        table.add_row(
            vuln_type,
            severity,
            signatures_text,
            vectors_text,
            examples_text
        )
    
    # Print the table
    console.print(table)
    console.print("\n[italic]Use the view_detection_library() function to see the full detection templates.[/italic]")

def format_examples(examples):
    """Convert a list of examples (which may be dicts) into a formatted string."""
    formatted = []
    for ex in examples:
        if isinstance(ex, dict):
            # Convert dict to a pretty JSON string
            formatted.append(json.dumps(ex, indent=2))
        else:
            formatted.append(str(ex))
    return "\n".join(formatted)

def display_detection_library(library):
    # If library is a string, attempt to convert it.
    if isinstance(library, str):
        try:
            library = json.loads(library)
        except Exception as e:
            console.print(f"[red]Failed to convert library string: {e}[/red]")
            return

    table = Table(title="Detection Pattern Library (Aggregated in Memory)")
    table.add_column("Vulnerability Type", style="cyan")
    table.add_column("Questions", style="magenta")
    table.add_column("Vulnerable Examples", style="red")
    table.add_column("Fixed Examples", style="green")
    
    for vuln_type, details in library.items():
        # If details is a string, try to parse it into a dictionary.
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception as e:
                console.print(f"[red]Failed to parse details for {vuln_type}: {e}[/red]")
                details = {}
        # If details is a list, use the first element (if available)
        if isinstance(details, list):
            details = details[0] if details else {}
        questions = "\n".join(details.get("questions", []))
        vuln_examples = format_examples(details.get("vulnerable_examples", []))
        fixed_examples = format_examples(details.get("fixed_examples", []))
        table.add_row(vuln_type, questions, vuln_examples, fixed_examples)
    console.print(table)

# ---------------------- UI Layout & Main Loop ----------------------
def render_layout() -> Panel:
    header = Panel("[bold magenta]SFA VectorEyes[/bold magenta]", padding=(1,2), style="on blue")
    menu_table = Table.grid(padding=1)
    menu_table.add_column(justify="left")
    menu_table.add_row("[bold blue]1.[/bold blue] Vectorize Report")
    menu_table.add_row("[bold blue]2.[/bold blue] View Reports")
    menu_table.add_row("[bold blue]3.[/bold blue] Delete Reports")
    menu_table.add_row("[bold blue]4.[/bold blue] Build & Save Detection Library")
    menu_table.add_row("[bold blue]5.[/bold blue] View Detection Library")
    menu_table.add_row("[bold blue]6.[/bold blue] Delete Detection Library Entries")
    menu_table.add_row("[bold blue]7.[/bold blue] Update API Keys")
    menu_table.add_row("[bold blue]8.[/bold blue] Exit")
    menu = Panel(menu_table, title="Main Menu", border_style="bright_green", padding=(1,2))
    tasks_table = Table(show_header=False, box=None, padding=(0,1))
    with task_lock:
        for key, status in task_status.items():
            tasks_table.add_row(key, status)
    body = Panel(tasks_table, title="Background Tasks", padding=(0,1), border_style="yellow")
    layout = Table.grid(expand=True)
    layout.add_row(header)
    layout.add_row(menu)
    layout.add_row(body)
    outer = Panel(layout, padding=(2, 6), border_style="magenta")
    return outer

def update_api_keys():
    """Update API keys for the current session only - keys are not saved to disk"""
    global OPENROUTER_API_KEY, USE_API, DEFAULT_MODEL, DEFAULT_OLLAMA_MODEL
    
    console.print(Panel.fit(
        "[bold]API Key Management[/bold]\n\n"
        "Update your API keys for the current session.\n"
        "[bold cyan]For security, keys are only stored in memory and not saved to disk.[/bold cyan]",
        title="Session-Based API Key Management",
        border_style="blue"
    ))
    
    # Display current settings
    settings_table = Table(show_header=False, box=SIMPLE)
    settings_table.add_column("Setting", style="cyan")
    settings_table.add_column("Value", style="green")
    
    settings_table.add_row("API Provider", USE_API)
    if USE_API == "openrouter":
        # Show masked API key if available
        masked_key = "Not set"
        if OPENROUTER_API_KEY:
            # Mask the key, showing only first 4 and last 4 characters
            if len(OPENROUTER_API_KEY) > 8:
                masked_key = OPENROUTER_API_KEY[:4] + "*" * (len(OPENROUTER_API_KEY) - 8) + OPENROUTER_API_KEY[-4:]
            else:
                masked_key = "*" * len(OPENROUTER_API_KEY)
        settings_table.add_row("OpenRouter API Key", masked_key)
        settings_table.add_row("Default Model", DEFAULT_MODEL)
    else:
        settings_table.add_row("Ollama Model", DEFAULT_OLLAMA_MODEL)
    
    console.print(settings_table)
    console.print("")
    
    # Menu options
    options = [
        "Update OpenRouter API Key",
        "Switch to Ollama (local)",
        "Switch to OpenRouter (cloud)",
        "Update Default Model",
        "Back to Main Menu"
    ]
    
    for i, option in enumerate(options, 1):
        console.print(f"[bold blue]{i}.[/bold blue] {option}")
    
    choice = Prompt.ask("Select an option", choices=[str(i) for i in range(1, len(options) + 1)], default="5")
    
    if choice == "1":  # Update OpenRouter API Key
        new_key = Prompt.ask("Enter your OpenRouter API key", password=True)
        if new_key.strip():
            OPENROUTER_API_KEY = new_key
            USE_API = "openrouter"  # Switch to OpenRouter when key is provided
            console.print("[green]OpenRouter API key updated for this session.[/green]")
        else:
            console.print("[yellow]No API key provided. Key not updated.[/yellow]")
    
    elif choice == "2":  # Switch to Ollama
        USE_API = "ollama"
        console.print("[green]Switched to Ollama for local LLM processing.[/green]")
    
    elif choice == "3":  # Switch to OpenRouter
        if OPENROUTER_API_KEY:
            USE_API = "openrouter"
            console.print("[green]Switched to OpenRouter for cloud LLM processing.[/green]")
        else:
            console.print("[yellow]No OpenRouter API key available. Please set a key first.[/yellow]")
            new_key = Prompt.ask("Enter your OpenRouter API key", password=True)
            if new_key.strip():
                OPENROUTER_API_KEY = new_key
                USE_API = "openrouter"
                console.print("[green]OpenRouter API key set and provider selected.[/green]")
    
    elif choice == "4":  # Update Default Model
        if USE_API == "openrouter":
            models = [
                "deepseek/deepseek-r1-distill-llama-70b:free",
                "deepseek/deepseek-r1:32b",
                "anthropic/claude-3-sonnet",
                "anthropic/claude-3-opus",
                "meta-llama/llama-3-70b-instruct",
                "google/gemini-pro"
            ]
            console.print("[bold]Available OpenRouter Models:[/bold]")
            for i, model in enumerate(models, 1):
                console.print(f"[bold blue]{i}.[/bold blue] {model}")
            model_choice = Prompt.ask("Select a model or enter a custom model ID", default="1")
            
            try:
                model_index = int(model_choice) - 1
                if 0 <= model_index < len(models):
                    DEFAULT_MODEL = models[model_index]
                else:
                    DEFAULT_MODEL = model_choice  # Use input as custom model ID
            except ValueError:
                DEFAULT_MODEL = model_choice  # Use input as custom model ID
                
            console.print(f"[green]Default model updated to: {DEFAULT_MODEL}[/green]")
        else:
            models = ["deepseek-r1:32b", "gemma:2b", "llama3:8b", "phi3:mini"]
            console.print("[bold]Available Ollama Models:[/bold]")
            for i, model in enumerate(models, 1):
                console.print(f"[bold blue]{i}.[/bold blue] {model}")
            model_choice = Prompt.ask("Select a model or enter a custom model ID", default="1")
            
            try:
                model_index = int(model_choice) - 1
                if 0 <= model_index < len(models):
                    DEFAULT_OLLAMA_MODEL = models[model_index]
                else:
                    DEFAULT_OLLAMA_MODEL = model_choice  # Use input as custom model ID
            except ValueError:
                DEFAULT_OLLAMA_MODEL = model_choice  # Use input as custom model ID
                
            console.print(f"[green]Default Ollama model updated to: {DEFAULT_OLLAMA_MODEL}[/green]")
    
    # Always pause before returning to main menu
    console.input("\nPress Enter to return to the Main Menu...")

def main():
    init_db()
    init_detection_library_table()
    console.clear()
    
    # Initialize API keys if available
    global OPENROUTER_API_KEY, USE_API, DEFAULT_MODEL, DEFAULT_OLLAMA_MODEL
    # Prompt for OpenRouter API key if not in environment
    if not OPENROUTER_API_KEY:
        console.print(Panel.fit(
            "[bold]API Key Selection[/bold]\n\n"
            "You can use Ollama (local) or OpenRouter (cloud) for LLM services.\n"
            "OpenRouter provides access to more powerful models but requires an API key.\n"
            "[bold cyan]For security, your API key will only be stored in memory for this session.[/bold cyan]",
            title="Welcome to SFA VectorEyes",
            border_style="blue"
        ))
        
        use_openrouter = Prompt.ask(
            "Would you like to use OpenRouter?", 
            choices=["yes", "no"], 
            default="no"
        )
        
        if use_openrouter.lower() == "yes":
            OPENROUTER_API_KEY = Prompt.ask("Enter your OpenRouter API key", password=True)
            if OPENROUTER_API_KEY:
                USE_API = "openrouter"
                console.print("[green]OpenRouter API key set for this session (will not be saved).[/green]")
            else:
                USE_API = "ollama"
                console.print("[yellow]No API key provided, defaulting to Ollama.[/yellow]")
        else:
            USE_API = "ollama"
            console.print("[cyan]Using Ollama for local LLM processing.[/cyan]")
    else:
        USE_API = "openrouter"
        console.print("[green]Using OpenRouter API key from environment variable.[/green]")
    
    console.print("[green]Loading embedding model...[/green]")
    # Using our simplified embedding approach instead of SentenceTransformer
    console.print("[yellow]Using simplified embedding method (no external model required)[/yellow]")
    model_instance = None  # No model needed for our simplified embedding
    executor = ThreadPoolExecutor(max_workers=2)
    futures = []
    while True:
        console.clear()
        outer_layout = render_layout()
        console.print(outer_layout)
        choice = console.input("[bold yellow]Select an option (1-8):[/bold yellow] ").strip()
        if choice == "1":
            url = console.input("Enter URL to a Markdown report or GitHub repo: ").strip()
            report_key = hashlib.sha256(url.encode("utf-8")).hexdigest()
            with task_lock:
                task_status[report_key] = "Task submitted"
            if url.lower().endswith(".md") or "issues" in url:
                future = executor.submit(process_single_file, url, model_instance)
            else:
                future = executor.submit(process_repo, url, model_instance)
            futures.append(future)

        elif choice == "2":
            console.clear()
            view_reports()
            console.input("Press Enter to return...")

        elif choice == "3":
            delete_reports()
            console.input("Press Enter to return...")

        elif choice == "4":
            # Build and save detection library using LLM-based clustering
            library = build_detection_library()
            display_detection_library(library)
            save_detection_library_to_db(library)
            console.input("Press Enter to return...")

        elif choice == "5":
            console.clear()
            view_detection_library()
            console.input("Press Enter to return...")

        elif choice == "6":
            delete_detection_library_entries()
            console.input("Press Enter to return...")

        elif choice == "7":
            # API Key Management
            # Handle API key updates for the current session
            update_api_keys()
                
        elif choice == "8":
            stop_choice = console.input("Stop running tasks? (Y/N): ").strip().lower()
            if stop_choice == "y":
                for f in futures:
                    f.cancel()
                executor.shutdown(wait=False)
            else:
                for f in as_completed(futures):
                    try:
                        f.result()
                    except Exception as e:
                        console.print(f"Task error: {e}")
                executor.shutdown(wait=True)
            console.print("[green]Exiting...[/green]")
            break

        else:
            console.print("[red]Invalid option. Try again.[/red]")
        time.sleep(0.5)

if __name__ == "__main__":
    main()
