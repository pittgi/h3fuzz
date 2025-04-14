import time
import asyncio
from numpy import random
from request import Request
from grammar import Grammar, NonTerminal, Header, Terminal, Data
from mutation import FillUntilMax
from utilities import TestState, TestResult
from qh3.quic.connection import QuicConnectionState


class H3Fuzzer:
    def __init__(self,
                 logger,
                 grammar: Grammar,
                 authority,
                 path,
                 num_fuzzes,
                 seed,
                 timeout: float):
        self.state = TestState.INIT
        self.__logger = logger
        self.__grammar = grammar
        self.__max_name_chars = 16
        self.__max_value_chars = 16
        self.__num_tests = 0
        self.__num_fuzzes = num_fuzzes
        self.__authority = authority
        self.__path = path
        self.__timeout = timeout
        self.__random = random.default_rng(seed)

    async def run_tests(self, http_request, connection_state):
        self.state = TestState.RUNNING
        while self.__num_tests < self.__num_fuzzes:
            if connection_state() != QuicConnectionState.CONNECTED:
                self.state = TestState.WAITING_FOR_NEW_CLIENT
                return
            self.__num_tests += 1
            request = self.__get_fuzz()
            result = None
            try:
                resp = await asyncio.wait_for(http_request(request.headers,
                                                           request.data),
                                              timeout=self.__timeout)
            except TimeoutError:
                resp = None
            except Exception as e:
                self.__logger.critical(str(e))
                self.state = TestState.FINISHED_WITH_ERROR
            result = request.evaluate_response(resp)
            self.__logger.info(f"{self.__num_tests}/{self.__num_fuzzes} fuzz[{request.request_id}]: {result.name}")
        self.state = TestState.FINISHED

    def set_max_name_chars(self, max: int):
        self.__max_name_chars = max
    
    def set_max_value_chars(self, max: int):
        self.__max_value_chars = max

    def __get_fuzz(self) -> Request:
        sequence = []
        sequence_is_legal = True
        while sequence_is_legal:
            # Init sequence and check if start is illegal
            sequence = [self.__grammar.get_nonterminal("start")]
            if sequence[0].is_illegal:
                sequence_is_legal = False
            # Iteratively extend sequence until only headers remain
            while not all(self.__is_header_or_data(item) for item in sequence):
                new_sequence = []
                for item in sequence:
                    if isinstance(item, Header):
                        new_sequence.append(item)
                    elif isinstance(item, Data):
                        self.__data = item.load
                    elif isinstance(item, NonTerminal):
                        extended_item = self.__extend_nonterminal(item.name)
                        if sequence_is_legal:
                            if any(item.is_illegal for item in extended_item):
                                sequence_is_legal = False
                        if extended_item is not None:
                            new_sequence.extend(extended_item)
                    else:
                        raise TypeError
                sequence = new_sequence
        return Request(self.__logger,
                       sequence,
                       self.__grammar,
                       self.__authority,
                       self.__path,
                       self.__max_name_chars,
                       self.__max_value_chars,
                       False,
                       self.__random)

    def __is_header_or_data(self, object: NonTerminal):
        return (isinstance(object, Header) or isinstance(object, Data))

    def __extend_nonterminal(self, nonterminal_str):
        nonterminal = self.__grammar.get_nonterminal(nonterminal_str)
        choice = self.__choice(nonterminal.derivatives,
                               nonterminal.probabilities)
        extended = []
        if choice is None:
            return None
        for obj in choice:
            new_obj = self.__grammar.get_nonterminal(obj)
            extended.append(new_obj)
        if nonterminal.permutationable:
            return self.__random.permutation(extended)
        else:
            return extended

    def __choice(self, options, probabilities):
        index = self.__random.choice(list(range(len(options))),
                                     p=probabilities)
        return options[index]
