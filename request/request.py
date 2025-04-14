import os
import time
import logging

from grammar import Grammar
from utilities import TestResult, MaliciousLoad, Header, Data, Terminal
from mutation import FillUntilMax, AddMax

class Request:
    request_id = 0
    def __init__(self,
                 logger: logging.Logger,
                 sequence: list[str],
                 grammar: Grammar,
                 authority: bytes,
                 path: bytes,
                 max_name_chars: int,
                 max_value_chars: int,
                 static: bool,
                 random_generator,
                 malicious = None):
        self.request_id = Request.request_id
        Request.request_id += 1
        self.headers = []
        self.data = None
        self.__backend_headers = None
        self.__backend_data = None
        self.__logger = logger
        self.__max_name_chars = max_name_chars
        self.__max_value_chars = max_value_chars
        self.__grammar = grammar
        self.__path = path
        self.__random = random_generator
        if malicious is None:
            self.__malicious = MaliciousLoad([], [])
        else:
            for load in malicious:
                all = []
                chars = []
                if isinstance(load, tuple):
                    chars.append(load)
                else:
                    all.append(load)
            self.__malicious = MaliciousLoad(all, chars)
        self.__build(sequence, authority, path, static)

    def get_malicious(self):
        return self.__malicious
    
    def __log_requests(self, result: TestResult, status_code):
        if result == TestResult.ACCEPTED or result == TestResult.MODIFIED:
            data_info = f"\nMALICIOUS: {self.__malicious}\nHEADERS: {self.headers}"
            if self.data is not None:
                data_info += f"\nDATA: {self.data}"
            if self.__backend_headers is not None:
                data_info += f"\nHEADERS RECIEVED: {self.__backend_headers}"
            if self.__backend_data is not None:
                data_info += f"\nBODY RECIEVED: {self.__backend_data}"
            self.__logger.log(logging.REQUEST, f"[{self.request_id}] {result.name} {data_info}")
        return

    def __build(self, sequence, authority, path, static):
        for object in sequence:
            if isinstance(object, str):
                object = self.__grammar.get_nonterminal(object)
            if isinstance(object, Data):
                self.data = object.load
                continue
            if not isinstance(object, Header):
                raise TypeError
            name = self.__build_terminal(object.name_terminal,
                                         self.__max_name_chars,
                                         authority,
                                         path,
                                         static)
            value = self.__build_terminal(object.value_terminal,
                                          self.__max_value_chars,
                                          authority,
                                          path,
                                          static)
            self.headers.append((name, value))
        self.headers.append((b"smuggling-id", str(self.request_id).encode()))
    
    def __build_terminal(self,
                         terminal: Terminal,
                         max_chars: int,
                         authority,
                         path,
                         static):
        choice = None
        if static:
            choice = terminal.terminals[0]
        else:
            choice = self.__choice(terminal.terminals,
                                   terminal.terminals_probabilities)
        choice = choice.replace(b"<authority>", authority)
        choice = choice.replace(b"<path>", path)
        if terminal.is_illegal:
            if choice not in [b":method", b":authority", b":path", b":scheme"]:
                self.__malicious.all.append(choice)
        if not static:
            # Apply mutations
            if terminal.mutations is not None and terminal.mutations != []:
                mutations = self.__choice(terminal.mutations,
                                          terminal.mutations_probabilities)
                if mutations is not None:
                    for mutation_str in mutations:
                        mutation = self.__grammar.get_mutation(mutation_str)
                        if isinstance(mutation, (FillUntilMax, AddMax)):
                            choice, m = mutation.apply(choice, max_chars)
                        else:
                            choice, m = mutation.apply(choice)
                        if not isinstance(m, MaliciousLoad):
                            raise TypeError
                        if m.all is not None:
                            self.__malicious.all.extend(m.all)
                        if m.chars is not None:
                            self.__malicious.chars.extend(m.chars)
                    self.__malicious.all.append(choice)
        self.__add_normalized_malicious()
        return choice

    def __evaluate_response(self, response):
        status_code = None
        if self.__malicious.all == []:
                return TestResult.REQUEST_NOT_MALFORMED, status_code
        result = None
        backend_request = self.__read_request_from_file()
        if backend_request is not None:
            self.__backend_headers = backend_request[0]
            self.__backend_data = backend_request[1]
        if self.__backend_headers is not None:
            if self.__malicious_reached_backend(self.__backend_headers):
                return TestResult.ACCEPTED, status_code
            else:
                return TestResult.MODIFIED, status_code
        else:
            if response is None:
                result = TestResult.TIMEOUT
            else:
                status_code = response[0].headers[0][1]
                if status_code == b'200':
                    raise Exception("Backend did not write request but" \
                                    "proxy responded with 200 OK")
                result = TestResult.REJECTED
        # Report TIMEOUT and REJECTED to char table
        for char_tuple in self.__malicious.chars:
            char_table = self.__grammar.get_char_table(char_tuple[0])
            char_table.report_result(char_tuple[1], result)
        return result, status_code

    def evaluate_response(self, response):
        result, status_code = self.__evaluate_response(response)
        self.__log_requests(result, status_code)
        return result
    
    def __add_normalized_malicious(self):
        to_be_added = []
        for malicious in self.__malicious.all:
            if malicious.startswith(b':'):
                continue
            allowed = {
                45,               # '-'
                *range(65, 91),   # A-Z
                *range(97, 123)   # a-z
            }
            if not all(b in allowed for b in malicious):
                continue
            if malicious[0] == b'-':
                continue
            malicious_str = malicious.decode()
            lowered = malicious_str.lower()
            canoncial = self.__make_canonical(lowered).encode()
            if canoncial not in self.__malicious.all:
                to_be_added.append(canoncial)
        self.__malicious.all.extend(to_be_added)

    def __make_canonical(self, b: str) -> str:
        make_uppercase = False
        output = b[0].capitalize()
        for char in b[1:]:
            if make_uppercase:
                output += char.capitalize()
                make_uppercase = False
                continue
            if char == '-':
                make_uppercase = True
            output += char
        return output
    
    def __read_request_from_file(self):
        tries = 0
        while True:
            tries += 1
            if not os.path.exists("./servers/request"):
                return None
            time.sleep(0.1) ## Race condition
            f = open("./servers/request", "rb")
            request = f.read()
            if not request.startswith(b"####REQ_ID_"):
                if tries > 1:
                    raise SyntaxError("request-file does not start with ####REQ_ID_")
                else:
                    print("HAD TO WAIT!")
                    time.sleep(0.1)
            else:
                break
        request = request.removeprefix(b"####REQ_ID_")
        id = self.__read_until_signal(request, b"####")
        if id == b'None':
            return None
        if int(id) != self.request_id:
            return None
        request = request.removeprefix(id + b"####")
        headers, body = self.__read_data(request)
        return headers, body
    
    def __read_until_signal(self, request: bytes, signal: bytes):
        index = 0
        found = False
        while index < len(request) and not found:
            if request.startswith(signal, index):
                found = True
            else:
                index += 1
        if not found:
            raise SyntaxError(f"Expected {signal} but did not find it")
        return request[:index]
                
    def __read_data(self, request: bytes):
        headers = {}
        body = None
        found_end_signal = False
        has_body = False
        while not found_end_signal:
            if not request.startswith(b"####H_NAME####"):
                if request.startswith(b"####REQ_END####"):
                    found_end_signal = True
                elif request.startswith(b'####BODY####'):
                    found_end_signal = True
                    has_body = True
                else:
                    raise SyntaxError(f"Expected REQ_END or H_NAME or BODY but got {request.decode()}")
            else:
                request = request.removeprefix(b"####H_NAME####")
                h_name = self.__read_until_signal(request, b"####H_VALUE####")
                request = request.removeprefix(h_name + b"####H_VALUE####")
                h_value = self.__read_until_signal(request, b"####")
                request = request.removeprefix(h_value)
                headers[h_name] = h_value
        if has_body:
            request = request.removeprefix(b'####BODY####')
            body = request.removesuffix(b'####REQ_END####')
        return headers, body

    
    def __choice(self, options, probabilities):
        index = self.__random.choice(list(range(len(options))),
                                     p=probabilities)
        return options[index]

    def __malicious_reached_backend(self, headers: dict):
        found = False
        accepted_chars = []
        modified_chars = []
        for char_tuple in self.__malicious.chars:
            for name, value in headers.items():
                if char_tuple[1][0] in name or char_tuple[1][0] in value:
                    if char_tuple not in accepted_chars:
                        accepted_chars.append(char_tuple)
                        if char_tuple in modified_chars:
                            modified_chars.remove(char_tuple)
                    found = True
                else:
                    if char_tuple not in modified_chars and \
                       char_tuple not in accepted_chars:
                        modified_chars.append(char_tuple)
        for malicious in self.__malicious.all:
            for name, value in headers.items():
                if malicious in name or malicious in value:
                    found = True
        for char in accepted_chars:
            char_table = self.__grammar.get_char_table(char[0])
            char_table.report_result(char[1], TestResult.ACCEPTED)
            self.__malicious.chars.remove(char)
        for char in modified_chars:
            char_table = self.__grammar.get_char_table(char[0])
            char_table.report_result(char[1], TestResult.MODIFIED)
            self.__malicious.chars.remove(char)
        return found
        
