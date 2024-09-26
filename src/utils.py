import logging

def setup_logging(log_file='logs.log'):
    """Configure logging for the project."""
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s:%(levelname)s:%(message)s'
    )