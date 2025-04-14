from numpy import random
from utilities import CharTable, MaliciousLoad


class Mutation:
    def __init__(self, name, char_table, char_position, quantity, seed):
        self._name = name
        self._char_position = char_position
        self._char_table = char_table
        self._quantity = quantity
        self._random = random.default_rng(seed)
        if self._char_position is None:
            self._char_position = "all"

    def apply(self, bytes: bytes) -> bytes:
        raise NotImplementedError

    def _choice(self, options, probabilities):
        if len(options) <= 0:
            return None
        index = self._random.choice(list(range(len(options))),
                              p=probabilities)
        return options[index]


class InsertChar(Mutation):
    def __init__(self,
                 name,
                 grammar,
                 char_table,
                 char_position,
                 quantity,
                 seed):
        self._grammar = grammar
        super().__init__(name, char_table, char_position, quantity, seed)

    def apply(self, input: bytes, forced_choice = None) -> bytes:
        mutated = input
        all_malicious = []
        malicious_chars = []
        char_table = self._grammar.get_char_table(self._char_table)
        if not isinstance(char_table, CharTable):
            raise TypeError
        for i in range(self._quantity):
            if forced_choice is None:
                choice = self._choice(char_table.chars,
                                      char_table.probabilities)
                if choice is None:
                    return input, MaliciousLoad(None, None)
            else:
                choice = forced_choice
            if not isinstance(choice, tuple):
                    raise TypeError
            if not isinstance(choice[0], bytes):
                raise TypeError
            if not isinstance(choice[1], int):
                raise TypeError
            if choice[1] not in [-1, 0, 1]:
                raise ValueError
            insert_pos = choice[1]
            match self._char_position:
                case "all":
                    if insert_pos == -1:
                        insert_pos = len(input)
                case "prefix":
                    insert_pos = 0
                case "infix":
                    insert_pos = self._random.integers(1, len(input) - 1)
                case "postfix":
                    insert_pos = len(input)
            mutated = mutated[:insert_pos] + choice[0] + mutated[insert_pos:]
            if char_table.illegal_in is not None:
                all_malicious.append(choice[0])
                if (self._char_table, choice) not in malicious_chars:
                    malicious_chars.append((self._char_table, choice))
            malicious_load = MaliciousLoad(all_malicious, malicious_chars)
        return mutated, malicious_load


class FillUntilMax(InsertChar):
    def __init__(self, name, grammar, char_table, char_position, offset, seed):
        self._offset = offset
        if self._offset is None:
            self._offset = 0
        super().__init__(name, grammar, char_table, char_position, None, seed)

    def apply(self, bytes: bytes, max: int) -> bytes:
        self._quantity = max + self._offset - len(bytes)
        return InsertChar.apply(self, bytes)


class AddMax(InsertChar):
    def __init__(self, name, grammar, char_table, char_position, offset, seed):
        self._offset = offset
        if self._offset is None:
            self._offset = 0
        super().__init__(name, grammar, char_table, char_position, None, seed)

    def apply(self, bytes: bytes, max: int) -> bytes:
        self._quantity = max + self._offset
        return InsertChar.apply(self, bytes)


class ReplaceWithUppercase(Mutation):
    def __init__(self, name, quantity, seed):
        super().__init__(name, None, None, quantity, seed)

    def apply(self, stream: bytes) -> bytes:
        malicious = []
        mutated = stream
        for i in range(self._quantity):
            byte_is_ascii_lowercase = False
            pos = None
            # Find lower-case ascii byte
            while not byte_is_ascii_lowercase:
                pos = self._random.integers(0, len(mutated))
                byte_is_ascii_lowercase = 97 <= mutated[pos] <= 122
            # Replace it with upper-case ascii byte
            uppercase_byte = bytes([mutated[pos] - 32])
            mutated = mutated[:pos] + uppercase_byte + mutated[pos + 1:]
            malicious.append(uppercase_byte)
        return mutated, MaliciousLoad(malicious, None)


class DeleteChar(Mutation):
    def __init__(self, name, char_position, quantity, seed):
        super().__init__(name, None, char_position, quantity, seed)

    def apply(self, stream: bytes) -> bytes:
        mutated = stream
        for i in range(self._quantity):
            pos = None
            match self._char_position:
                case "all":
                    pos = self._random.integers(0, len(mutated))
                case "prefix":
                    pos = 0
                case "postfix":
                    pos = len(mutated) - 1
                case "infix":
                    pos = self._random.integers(1, len(mutated) - 1)
            mutated = mutated[:pos] + mutated[pos + 1:]
        return mutated, MaliciousLoad(None, None)
