import argparse
import logging
import asyncio
import os
from numpy import random
from h3clientmanager import H3ClientManager
from testmanager import TestManager
from datetime import datetime


import logging
from datetime import datetime

def init_logger(logger: logging.Logger, debug_mode: bool):
    # Define custom REQUEST level if not already defined
    if not hasattr(logging, 'REQUEST'):
        logging.REQUEST = 25  # Between INFO (20) and WARNING (30)
        logging.addLevelName(logging.REQUEST, 'REQUEST')
    
    now = datetime.now()
    date_time = now.strftime("%d-%m-%Y_%H-%M-%S")
    main_filename = f"./logs/h3fuzz_{date_time}.log"
    request_filename = f"./logs/h3fuzz_{date_time}_requests.log"  # Separate file for REQUEST logs
    
    # Set logger's level based on debug mode
    logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
    
    # Common log format
    log_format_standard = "%(asctime)s [%(levelname)-5.5s]  %(message)s"
    log_format_requests = "%(asctime)s %(message)s"
    formatter_std = logging.Formatter(log_format_standard)
    formatter_req = logging.Formatter(log_format_requests)
    
    # Main file handler (excludes REQUEST logs)
    main_file_handler = logging.FileHandler(main_filename)
    main_file_handler.setFormatter(formatter_std)
    main_file_handler.addFilter(lambda record: record.levelno != logging.REQUEST)
    
    # Console handler (excludes REQUEST logs)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter_std)
    console_handler.addFilter(lambda record: record.levelno != logging.REQUEST)
    
    # Dedicated handler for REQUEST logs
    request_file_handler = logging.FileHandler(request_filename)
    request_file_handler.setLevel(logging.REQUEST)
    request_file_handler.setFormatter(formatter_req)
    request_file_handler.addFilter(lambda record: record.levelno == logging.REQUEST)
    
    # Add all handlers to the logger
    logger.addHandler(main_file_handler)
    logger.addHandler(console_handler)
    logger.addHandler(request_file_handler)


def parse_args(parser: argparse.ArgumentParser):
    parser.add_argument(
        "url", type=str, help="the URL to query (must be HTTPS)"
    )
    parser.add_argument(
        "-g",
        "--grammar",
        type=str,
        help="filepath to JSON file containing grammar"
    )
    parser.add_argument(
        "-b",
        "--boundary",
        type=int,
        help="skips the header length test and sets boundary to desired size"
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="sets logger-level to debug"
    )
    parser.add_argument(
        "-n",
        "--num-fuzzes",
        type=int,
        help="the number of fuzzes"
    )
    parser.add_argument(
        "-s",
        "--seed",
        type=int,
        default=None,
        help="specify the seed for the random-generator"
    )
    parser.add_argument(
        "--secrets-log",
        type=str,
        help="log http/3 secrets to specified file for use with wireshark"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.5,
        help="time the client waits for a server-response in seconds"
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from specified file"
    )
    return parser.parse_args()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP/3 RFC 9114 fuzzer")
    args = parse_args(parser)

    logger = logging.getLogger(__name__)
    init_logger(logger, args.debug)

    h3clientmanager = H3ClientManager(logger=logger,
                                      url=args.url,
                                      ca_certs=args.ca_certs,
                                      secrets_log=args.secrets_log)
    testmanager = TestManager(logger=logger,
                              h3clientmanager=h3clientmanager,
                              url=args.url,
                              grammar_path=args.grammar,
                              num_fuzzes=args.num_fuzzes,
                              seed=args.seed,
                              timeout= args.timeout)
    asyncio.run(testmanager.run())
