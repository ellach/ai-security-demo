# injecagent/tools.py
import os
from langchain.tools import tool

WORKSPACE = os.path.join(os.path.dirname(__file__))

@tool
def list_files(directory: str = ".") -> str:
    """List all files in the workspace directory."""
    try:
        target = os.path.join(WORKSPACE, directory)
        files = os.listdir(target)
        result = []
        for f in files:
            full_path = os.path.join(target, f)
            size = os.path.getsize(full_path)
            result.append(f"- {f} ({size} bytes)")
        return "\n".join(result)
    except Exception as e:
        return f"Error listing files: {str(e)}"

@tool
def read_file(filename: str) -> str:
    """Read the contents of a file in the workspace."""
    try:
        filepath = os.path.join(WORKSPACE, filename)
        with open(filepath, "r") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"

@tool
def write_file(filename: str, content: str) -> str:
    """Write content to a file in the workspace."""
    try:
        filepath = os.path.join(WORKSPACE, filename)
        with open(filepath, "w") as f:
            f.write(content)
        return f"Successfully wrote to {filename}"
    except Exception as e:
        return f"Error writing file: {str(e)}"