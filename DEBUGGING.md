# Debugging the Web Security Tool in VSCode

This guide explains how to set up and use debugging for both the FastAPI and Streamlit components of this application in Visual Studio Code.

## Prerequisites

1. Make sure you have installed the Python extension for VSCode.
2. Your virtual environment is set up and activated: `python -m venv venv` and `source venv/bin/activate` (Linux/Mac) or `venv\Scripts\activate` (Windows)
3. All dependencies are installed: `pip install -U -r requirements.txt`
4. Your `.env` file is properly configured with all required API keys

## Debug Configurations

The project includes the following debug configurations:

1. **FastAPI: main.py** - Starts the FastAPI server with debugging enabled
2. **Streamlit: app.py** - Starts the Streamlit app with debugging enabled
3. **Python: Current File** - Runs and debugs the currently open Python file

## How to Debug

### Starting a Debug Session

1. Open VSCode and make sure you're in the project workspace
2. Open the "Run and Debug" view (Ctrl+Shift+D or Cmd+Shift+D on Mac)
3. Select the appropriate configuration from the dropdown at the top of the Run view
4. Click the green "Start Debugging" button or press F5

### For Debugging the Full Application

To debug the complete application, you'll need to run both components:

1. First, start the FastAPI server by selecting "FastAPI: main.py" and pressing F5
2. Then, in a new VSCode window or by splitting your terminal, start the Streamlit app by selecting "Streamlit: app.py" and pressing F5

### Setting Breakpoints

1. Open any Python file in the project
2. Click in the left margin next to the line number where you want to pause execution
3. A red dot will appear, indicating a breakpoint
4. When execution reaches that line, it will pause and VSCode will show the debug controls

## Debugging AI Components

To debug the AI integration:

1. Add breakpoints in `utils/ai_client.py` to inspect the prompts and responses
2. Use the debug console (available when paused at a breakpoint) to inspect variables
3. Check the function calls to different AI services by adding breakpoints in the `_analyze_with_*` methods

## Debugging Security Scanners

For debugging the integration with security scanning tools:

1. Add breakpoints in the respective scanner files in the `analyzer/` directory
2. Monitor the execution of scanner commands and the processing of their results

## Debugging Tips

1. Use the "Debug Console" to evaluate expressions when paused at a breakpoint
2. The "Variables" view shows all local and global variables in the current scope
3. The "Watch" view allows you to monitor specific expressions
4. Use "Step Over" (F10) to execute the current line and stop at the next line
5. Use "Step Into" (F11) to step into function calls
6. Use "Step Out" (Shift+F11) to complete the current function and pause at the calling line
7. Use "Continue" (F5) to resume execution until the next breakpoint

## Troubleshooting

1. **Path Issues**: If you encounter path-related errors, ensure the `PYTHONPATH` is set correctly in the launch configurations
2. **API Connection Issues**: When debugging AI-related functionality, ensure your API keys are correctly set in the `.env` file
3. **Port Conflicts**: If you get "address already in use" errors, ensure no other instances of the application are running on the same ports