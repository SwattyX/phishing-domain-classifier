import logging
import re
from http import HTTPStatus

def setup_logging(log_file="logs.log"):
    # Configure logging for the project.
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s:%(levelname)s:%(message)s"
    )

def extract_status_code(log_string: str) -> str:
    match = re.search(r"HTTP Status:\s*(\d{3})", log_string)
    if match:
        code = int(match.group(1))
        try:
            # Get the description of the status code using HTTPStatus
            status_name = HTTPStatus(code).phrase
        except ValueError as ve:
            # Handle non-standard status codes
            status_name = "Unknown Status Code"
        return f"HTTP Status Code: {code} - {status_name}"
    else:
        return None
