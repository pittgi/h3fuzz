import asyncio
import time
from logging import Logger
from numpy import random
from qh3.quic.connection import QuicConnectionState
from grammar import Grammar
from h3fuzzer import H3Fuzzer
from h3statictest import H3StaticTest
from h3clientmanager import H3ClientManager
from h3lentest import HeaderValueLengthTest, HeaderNameLengthTest
from urllib.parse import urlparse
from utilities import TestPhase, TestState


class TestManager:
    def __init__(self,
                 logger: Logger,
                 url,
                 grammar_path: str | None,
                 num_fuzzes: int,
                 h3clientmanager: H3ClientManager,
                 seed: int | None,
                 timeout: float):
        req_authority = urlparse(url).netloc.encode()
        req_path = urlparse(url).path.encode()
        self.__logger = logger
        self.__seed = self.set_seed(seed)
        self.__test_phase = TestPhase.NORMAL_REQUEST
        self.__num_fuzzes = num_fuzzes
        self.__h3client = h3clientmanager
        self.__max_test_name = HeaderNameLengthTest(logger, url, timeout)
        self.__max_test_value = HeaderValueLengthTest(logger, url, timeout)
        self.__start_time = time.perf_counter()
        self.__grammar = Grammar(logger, grammar_path, self.__seed)
        self.__fuzzer = H3Fuzzer(logger,
                                 self.__grammar,
                                 req_authority,
                                 req_path,
                                 num_fuzzes,
                                 self.__seed,
                                 timeout)
        self.__static = H3StaticTest(logger,
                                     url,
                                     self.__grammar,
                                     req_authority,
                                     req_path,
                                     timeout)

    async def run(self):
        await self.__h3client.run_loop(self.test_pipeline)

    async def test_pipeline(self, http_request, connection_state):
        while True:
            if connection_state() != QuicConnectionState.CONNECTED:
                return True
            match self.__test_phase:
                case TestPhase.NORMAL_REQUEST:
                    success = await self.__normal_request_success(http_request)
                    if success:
                        self.__next_phase()
                    else:
                        self.__error_exit()
                case TestPhase.HEADER_NAME_LENGTH:
                    await self.__max_test_name.run_test(http_request)
                    match self.__max_test_name.state:
                        case TestState.FINISHED:
                            r = self.__max_test_name.result
                            self.__fuzzer.set_max_name_chars(r)
                            self.__logger.info(f"Header name max: {r} bytes")
                            self.__next_phase()
                        case TestState.FINISHED_WITH_ERROR:
                            self.__error_exit()
                        case TestState.WAITING_FOR_NEW_CLIENT:
                            return True
                        case TestState.INIT:
                            raise Exception("HNLT exited with state INIT")
                        case TestState.RUNNING:
                            raise Exception("HNLT exited with state RUNNING")
                case TestPhase.HEADER_VALUE_LENGTH:
                    await self.__max_test_value.run_test(http_request)
                    match self.__max_test_value.state:
                        case TestState.FINISHED:
                            r = self.__max_test_value.result
                            self.__fuzzer.set_max_value_chars(r)
                            self.__logger.info(f"Header value max: {r} bytes")
                            self.__next_phase()
                        case TestState.FINISHED_WITH_ERROR:
                            self.__error_exit()
                        case TestState.WAITING_FOR_NEW_CLIENT:
                            return True
                        case TestState.INIT:
                            raise Exception("HVLT exited with state INIT")
                        case TestState.RUNNING:
                            raise Exception("HVLT exited with state RUNNING")
                case TestPhase.STATIC:
                    await self.__static.run_test(http_request,
                                                 connection_state)
                    match self.__static.state:
                        case TestState.FINISHED:
                            self.__logger.info(f"Finished static tests")
                            self.__next_phase()
                        case TestState.FINISHED_WITH_ERROR:
                            self.__error_exit()
                        case TestState.WAITING_FOR_NEW_CLIENT:
                            return True
                        case TestState.INIT:
                            raise Exception("Static exited with state INIT")
                        case TestState.RUNNING:
                            raise Exception("Static exited with state RUNNING")
                case TestPhase.FUZZING:
                    await self.__fuzzer.run_tests(http_request,
                                                  connection_state)
                    match self.__fuzzer.state:
                        case TestState.FINISHED:
                            self.__logger.info(f"Finished fuzzing")
                            self.__next_phase()
                        case TestState.FINISHED_WITH_ERROR:
                            self.__error_exit()
                        case TestState.WAITING_FOR_NEW_CLIENT:
                            return True
                        case TestState.INIT:
                            raise Exception("Fuzzing exited with state INIT")
                        case TestState.RUNNING:
                            raise Exception("Fuzzing exited with state RUNNING")
                case TestPhase.FINISHED:
                    return False
        return False

    def set_seed(self, seed):
        if seed is None:
            generated_seed = random.randint(0, 2**32)
            self.__logger.info(f"Seed for reproducibility: {generated_seed}")
            return generated_seed
        else:
            self.__logger.info(f"Seed manually set to {seed}")
            return seed

    def __next_phase(self):
        match self.__test_phase:
            case TestPhase.NORMAL_REQUEST:
                self.__logger.info("Proceeding with header name length test")
                self.__test_phase = TestPhase.HEADER_NAME_LENGTH
            case TestPhase.HEADER_NAME_LENGTH:
                self.__logger.info("Proceeding with header value length test")
                self.__test_phase = TestPhase.HEADER_VALUE_LENGTH
            case TestPhase.HEADER_VALUE_LENGTH:
                self.__logger.info("Proceeding with static tests")
                self.__test_phase = TestPhase.STATIC
            case TestPhase.STATIC:
                if self.__num_fuzzes is not None:
                    self.__logger.info("Proceeding with fuzzing")
                    self.__test_phase = TestPhase.FUZZING
                else:
                    self.__logger.info("User did not specify number of tests: skipping fuzzing")
                    runtime = time.perf_counter() - self.__start_time
                    self.__logger.info(f"Runtime: {runtime} seconds")
                    self.__logger.info("Test finished without errors")
                    self.__test_phase = TestPhase.FINISHED
            case TestPhase.FUZZING:
                runtime = time.perf_counter() - self.__start_time
                self.__logger.info(f"Runtime: {runtime} seconds")
                self.__logger.info("Test finished without errors")
                self.__test_phase = TestPhase.FINISHED
            case TestPhase.FINISHED:
                raise Exception("Called __next_phase with TestPhase.FINISHED")
            case _:
                raise ValueError(f"unkown testphase {self.__test_phase}")

    def __error_exit(self):
        self.__logger.critical("Program exited unexpectedly")
        exit(-1)

    async def __normal_request_success(self, http_request):
        start_time = time.perf_counter()
        try:
            resp = await asyncio.wait_for(http_request(), timeout=2)
            t_spent = time.perf_counter() - start_time
            self.__logger.info(f"Respones after {t_spent} seconds")
            status_code = resp[0].headers[0][1]
            if status_code == b'200':
                self.__logger.info("Normal request recieved 200 OK")
                return True
            else:
                msg = "Reverse-Proxy did not answer with 200 OK"
        except Exception as e:
            msg = "Unmalformed request failed: " + str(e)
        self.__logger.critical(msg)
        return False
