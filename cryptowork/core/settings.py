import logging
import os
import sys

from dotenv import find_dotenv, load_dotenv
from loguru import logger

from cryptowork.core.logging import InterceptHandler

logger.info("Loading the settings from environ.")

load_dotenv(find_dotenv())

DEBUG = os.environ.get("DEBUG")
KEY = os.environ.get("KEY")
IV = os.environ.get("IV")

logger.debug(KEY)
logger.debug(IV)

logger.info("Loaded the settings.")

# logging configuration

LOGGING_LEVEL = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    handlers=[InterceptHandler(level=LOGGING_LEVEL)], level=LOGGING_LEVEL
)
logger.configure(handlers=[{"sink": sys.stderr, "level": LOGGING_LEVEL}])
