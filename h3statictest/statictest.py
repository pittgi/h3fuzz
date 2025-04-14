import asyncio
import time
from logging import Logger
from utilities import TestState, TestResult, CharTable, MaliciousLoad
from urllib.parse import urlparse
from grammar import Grammar, Header, Terminal
from mutation import InsertChar
from request import Request
from qh3.quic.connection import QuicConnectionState


class H3StaticTest:
    def __init__(self,
                 logger: Logger,
                 url: str,
                 grammar: Grammar,
                 authority :bytes,
                 path: bytes,
                 timeout: float):
        self.state = TestState.INIT
        self.result = None
        self.__grammar = grammar
        self.__authority = urlparse(url).netloc.encode()
        self.__path = urlparse(url).path.encode()
        self.__logger = logger
        self.__static_tests = []
        self.__static_chr_tests = []
        self.__static_results = {}
        self.__timeout = timeout
        self.__build_static_queue(authority, path)

    def __build_static_queue(self, authority: bytes, path: bytes):
        for pre_test_key, pre_test in self.__grammar.get_all_pre_tests():
            self.__static_tests.append((pre_test_key, pre_test))
        # build illegal char tests
        dummy_value = b"malformed"
        for char_table_key, char_table in self.__grammar.get_all_char_tables():
            mutation = InsertChar("",
                                  self.__grammar,
                                  char_table_key,
                                  "all",
                                  1,
                                  0)
            if not isinstance(char_table, CharTable):
                raise TypeError
            if char_table.illegal_in is None:
                continue
            for char in char_table.chars:
                name_bytes = dummy_value
                value_bytes = dummy_value
                name_bool = False
                value_bool = False
                if char_table.illegal_in == "header-name":
                    name_bytes, malicious = mutation.apply(dummy_value, char)
                    name_bool = True
                else:
                    value_bytes, malicious = mutation.apply(dummy_value, char)
                    value_bool = True
                name_terminal = Terminal([name_bytes], [1], [], None, name_bool)
                value_terminal = Terminal([value_bytes], [1], [], None, value_bool)
                header = Header("", name_terminal, value_terminal)
                request = Request(self.__logger,
                                  ["method-header", "scheme-header",
                                   "authority-header", "path-header", header],
                                  self.__grammar,
                                  authority,
                                  path,
                                  None,
                                  None,
                                  True,
                                  None,
                                  [char[0], (char_table_key, char)])
                illegal_char = malicious.chars[0][1]
                illegal_byte = illegal_char[0]
                illegal_pos = illegal_char[1]
                pos = "prefix"
                if illegal_pos == 1:
                    pos = "infix"
                elif illegal_pos == -1:
                    pos = "postfix"
                illegal_byte_str = f"0x{illegal_byte[len(illegal_byte)-1]:02x}"
                msg = f"{char_table_key}', {pos} '{illegal_byte_str}"
                self.__static_chr_tests.append((msg,
                                                request,
                                                char_table_key,
                                                char))
                


    async def run_test(self, http_request, connection_state):
        self.state = TestState.RUNNING
        while len(self.__static_tests) > 0 or len(self.__static_chr_tests) > 0:
            if connection_state() != QuicConnectionState.CONNECTED:
                self.state = TestState.WAITING_FOR_NEW_CLIENT
                return
            char_test = False
            if len(self.__static_tests) == 0:
                char_test = True
                test = self.__static_chr_tests.pop(0)
            else:
                test = self.__static_tests.pop(0)
            if not isinstance(test[1], Request):
                request = Request(self.__logger,
                                  test[1].sequence,
                                  self.__grammar,
                                  self.__authority,
                                  self.__path,
                                  None,
                                  None,
                                  True,
                                  None)
            else:
                request = test[1]
            try:
                request_id = request.request_id
                resp = await asyncio.wait_for(http_request(request.headers,
                                                           request.data),
                                              timeout=self.__timeout)
            except TimeoutError:
                resp = None
            except Exception as e:
                self.__logger.critical(str(e))
                self.state = TestState.FINISHED_WITH_ERROR
                return
            result = request.evaluate_response(resp)
            if not char_test:
                self.__grammar.report_pre_test_result(test[0], result)
            self.__logger.info(f"Static test id: {request_id} '{test[0]}': {result.name}")
        self.__grammar.apply_pre_test_actions()
        self.state = TestState.FINISHED
