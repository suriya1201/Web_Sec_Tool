# Inspectify


## Setup

1. Create venv in folder ```python -m venv venv```
2. Activate venv ```call venv/Scripts/activate.bat```
3. Install modules ```pip install -U -r requirements.txt```
4. Run this list of commands for the cmdline tools within the project folder:
```git clone https://github.com/commixproject/commix.git
git clone https://github.com/vladko312/SSTImap.git
cd SSTImap
pip install -U -r requirements.txt
cd ..
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -U -r requirements.txt```
5. Create .env file with the contents:
```
GEMINI_API_KEY=your_gemini_key
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key
ZAP_API_KEY=your_ZAP_key
#OLLAMA_BASE_URL=http://localhost:11434  # Optional
```
6. Go to Terminal -> Run Tasks... -> Start OWASP ZAP (May need to change the cwd in tasks.json to where your ZAP is)
7. With venv activated ```uvicorn main:app --reload --port 8001```
8. With venv activated on another terminal ```streamlit run app.py```