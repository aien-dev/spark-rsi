#!/usr/bin/env python3
import json
import os
import re
import sys
import urllib.request

MAX_URL = "http://127.0.0.1:18006/v1/chat/completions"
MODEL_ID = "atlas-lightning-omni"

def query_aien_streaming(system_prompt: str, user_prompt: str, max_tokens: int = 2048) -> str:
    payload = {
        "model": MODEL_ID,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "max_tokens": max_tokens,
        "stream": True,
        "temperature": 0.2
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(MAX_URL, data=data, headers={"Content-Type": "application/json"})
    
    content_parts = []
    reasoning_parts = []
    
    with urllib.request.urlopen(req, timeout=300) as resp:
        for line in resp:
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str or not line_str.startswith("data:"):
                continue
            raw_data = line_str[5:].strip()
            if raw_data == "[DONE]":
                break
            try:
                chunk = json.loads(raw_data)
                delta = chunk.get("choices", [{}])[0].get("delta", {})
                if "content" in delta and delta["content"]:
                    content_parts.append(delta["content"])
                    sys.stdout.write(delta["content"])
                    sys.stdout.flush()
                elif "reasoning" in delta and delta["reasoning"]:
                    reasoning_parts.append(delta["reasoning"])
            except Exception:
                continue
    
    full_content = "".join(content_parts).strip()
    if not full_content:
        full_content = "".join(reasoning_parts).strip()
    return full_content

def extract_code_block(text: str) -> str:
    pattern = r"```(?:rust)?\s*\n(.*?)```"
    matches = re.findall(pattern, text, re.DOTALL)
    if matches:
        return matches[-1].strip()
    return text.strip()

def sanitize_unslop(code: str) -> str:
    return code.replace("\u2014", ", ").replace("\u2013", "-")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: drive_aien_code.py <target_file> <prompt_file> [max_tokens]")
        sys.exit(1)
        
    target_path = sys.argv[1]
    prompt_path = sys.argv[2]
    max_tokens = int(sys.argv[3]) if len(sys.argv) > 3 else 2048
    
    with open(prompt_path, "r") as f:
        user_prompt = f.read()
        
    sys_prompt = (
        "You are AIEN, lead systems architect and principal native Rust systems engineer on NVIDIA DGX Spark.\n"
        "Generate clean, compiling, robust Rust code for spark-rsi.\n"
        "Strictly adhere to the anti-slop standard: ZERO em dashes (\\u2014), ZERO en dashes (\\u2013), ZERO buzzwords.\n"
        "Keep internal reasoning concise and emit ONLY the complete Rust code in a fenced markdown block."
    )
    
    print(f"[*] Driving AIEN via MAX streaming for {target_path} (max_tokens={max_tokens})...")
    raw = query_aien_streaming(sys_prompt, user_prompt, max_tokens=max_tokens)
    code = extract_code_block(raw)
    code = sanitize_unslop(code)
    
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    with open(target_path, "w") as f:
        f.write(code + "\n")
    print(f"\n[+] Successfully written {len(code)} bytes to {target_path}")
