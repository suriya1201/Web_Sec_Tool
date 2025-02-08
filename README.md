# Inspectify


## Setup

1. Create venv in folder ```python -m venv venv```
2. Activate venv ```call venv/Scripts/activate.bat```
2. ```pip install -r requirements.txt```
3. create .env file with the contents:
```
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key
#OLLAMA_BASE_URL=http://localhost:11434  # Optional
```
4. With venv activated ```uvicorn main:app --reload --port 8001```
5. With venv activated on another terminal ```streamlit run app.py```