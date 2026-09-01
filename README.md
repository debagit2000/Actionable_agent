# Actionable_agent
AI Agent which can take action 


------OLLAMA Setup---------------
curl -fsSL https://ollama.com/install.sh | sh - To install Ollama 
systemctl status ollama
systemctl edit ollama
ollama serve
ollama --version / ollama -v 
ss -lntp | grep 11434

-----OLLAMA ENV--------------------------
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:3b"

-----OLLAMA Models------------------

ollama pull <model name>
ollama list - to check the localy available models 
ollama run <model name> - to run any model directly - /bye to exit
ollama show <model name>
ollama ps
ollama stop <model name>
ollama rm <model name>
ollama cp <model name> <name>



-----Operate OLLAMA Model----------------

/api/generate - used for a single prompt 
/api/chat - role-based conversations


curl http://localhost:11434/api/generate \
-H "Content-Type: application/json" \
-d '{
"model": "qwen2.5:3b",
"prompt": "Explain Linux load average briefly.",
"stream": false
}'

----Payload example--------------
payload = {
        "model": MODEL_NAME,
        "messages": 
        [
          {
          "role": "system",
          "content": system_prompt
          },
          {
          "role": "user",
          "content": user_prompt
          }
        ],
        "stream": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_ctx": 8192
           },
        "keep_alive": "10m"
}












