from enum import Enum
from dataclasses import dataclass


class TestType(Enum):
    TRANSFER_ENCODING = 1
    CONTENT_LENGTH = 2
    PSEUDO_FILED_AFTER_REGULAR = 3
    CONFLICTING_HOST = 4
    INVALID_PSEUDO_HEADER = 5
    DUBLICATE_PSEUDO_HEADER = 6
    HEADER_VALUE = 7
    HEADER_NAME = 8


class TestResult(Enum):
    REJECTED = 1
    MODIFIED = 2
    TIMEOUT = 3
    ACCEPTED = 4
    REQUEST_NOT_MALFORMED = 5


class TestPhase(Enum):
    NORMAL_REQUEST = 1
    HEADER_NAME_LENGTH = 2
    HEADER_VALUE_LENGTH = 3
    STATIC = 4
    FUZZING = 5
    FINISHED = 6


class TestState(Enum):
    INIT = 1
    RUNNING = 2
    WAITING_FOR_NEW_CLIENT = 3
    FINISHED_WITH_ERROR = 4
    FINISHED = 5


@dataclass
class NonTerminal:
    name: str
    derivatives: list[list[str] | None]
    probabilities: list[float]
    permutationable: bool
    is_illegal: bool


@dataclass
class Terminal:
    terminals: list[str]
    terminals_probabilities: list[float]
    mutations: list[list]
    mutations_probabilities: list[float]
    is_illegal: bool


@dataclass
class Header:
    name: str
    name_terminal: Terminal
    value_terminal: Terminal


@dataclass
class Data:
    load: bytes
    is_illegal: bool = False


@dataclass
class PreTestAction:
    nonterminal: str
    derivative: int | None
    factor: float | None


@dataclass
class PreTest:
    sequence: list[Header]
    influence: dict[dict[list[PreTestAction]] | None]
    result: TestResult | None


@dataclass
class MaliciousLoad:
    all: list[bytes]
    chars: list[tuple[str, tuple[bytes, int]]] | None


class CharTable:
    def __init__(self,
                 chars: list[tuple[bytes, int]],
                 results: list[list[int, int]],
                 probabilities: list[float],
                 illegal_in: str | None,
                 laplace_alpha: float,
                 laplace_beta: float,
                 success_boost: float):
        self.chars = chars
        self.results = results
        self.probabilities = probabilities
        self.illegal_in = illegal_in
        self.__laplace_a = laplace_alpha
        self.__laplace_b = laplace_beta
        self.__success_boost = success_boost
        self.__sum_cache = len(chars) * (laplace_alpha / laplace_beta)
    
    def report_result(self,
                      object: tuple[bytes, int] | list[tuple[bytes, int]],
                      result: TestResult):
        if isinstance(object, tuple):
            char_list = [object]
        else:
            char_list = object
        match result:
            case TestResult.TIMEOUT:
                self.__report(char_list, False)
            case TestResult.REJECTED:
                self.__report(char_list, False)
            case TestResult.MODIFIED:
                self.__report(char_list, True)
            case TestResult.ACCEPTED:
                self.__drop(char_list)
            case _:
                raise Exception(f"{result.name} was reported to grammar")
            
    def __drop(self, input_list):
        char_list = input_list
        if not isinstance(char_list, list):
            raise TypeError
        index = 0
        while index < len(self.chars) and len(char_list) > 0:
            if self.chars[index] in char_list:
                char_list.remove(self.chars[index])
                self.__sum_cache -= self.__succes_rate(index)
                self.chars.pop(index)
                self.results.pop(index)
                self.probabilities.pop(index)
            index += 1
        if len(char_list) > 0:
            raise Exception("CharTable.__drop: char not found in table")
        self.__calculate_possibilities()
        
    def __report(self, input_list, success):
        char_list = input_list
        if not isinstance(char_list, list):
            raise TypeError
        index = 0
        while index < len(self.chars) and len(char_list) > 0:
            if self.chars[index] in char_list:
                char_list.remove(self.chars[index])
                self.__sum_cache -= self.__succes_rate(index)
                self.results[index][1] += 1
                if success:
                    self.results[index][0] += 1
                self.__sum_cache += self.__succes_rate(index)
            index += 1
        if len(char_list) > 0:
            raise Exception(f"CharTable.__report: {char_list[0]} not found in table")
        self.__calculate_possibilities()

    def __calculate_possibilities(self):
        highest_char = None
        highest_probability = 0.0
        for index, p in enumerate(self.probabilities):
            self.probabilities[index] = \
                self.__succes_rate(index) / self.__sum_cache
            if highest_probability < self.probabilities[index]:
                highest_char = self.chars[index]
                highest_probability = self.probabilities[index]
        # print(f"Highest probability: {highest_char} with {highest_probability} and {len(self.chars)} chars in table, mean: {1 / len(self.chars)}")

    def __succes_rate(self, index):
        successes = self.results[index][0]
        total = self.results[index][1]
        output = (successes + self.__laplace_a) / (total + self.__laplace_b)
        return output
