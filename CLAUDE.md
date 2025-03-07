# CLAUDE.md for Web_Sec_Tool

## Build/Run Commands
- Create environment: `python -m venv venv`
- Activate environment: `source venv/bin/activate` (Linux/Mac) or `venv\Scripts\activate` (Windows)
- Install dependencies: `pip install -U -r requirements.txt`
- Run FastAPI server: `uvicorn main:app --reload --port 8001`
- Run Streamlit app: `streamlit run app.py`
- Run tests: `python test_vulnerable.py`

## Code Style Guidelines
- **Naming**: Snake_case for files/variables, PascalCase for classes, UPPER_CASE for constants
- **Imports**: Group standard lib, third-party, then local imports with blank lines between
- **Documentation**: Use docstrings with type hints for functions and classes
- **Error handling**: Use try/except blocks with specific exceptions
- **Formatting**: 4-space indentation, 120 character line limit
- **Type hints**: Use proper type annotations from the typing module
- **Classes**: Follow Pydantic BaseModel for data models

## Security Tools
This project integrates multiple security scanners including ZAP, Wapiti, SQLMap, XSStrike, COMMIX, SSTImap, and a custom broken access scanner.