import json
import re
from logging import Logger
from dataclasses import dataclass
from mutation import (Mutation,
                      InsertChar,
                      DeleteChar,
                      FillUntilMax,
                      AddMax,
                      ReplaceWithUppercase)
from utilities import (Header,
                       NonTerminal,
                       Terminal,
                       Data,
                       PreTest,
                       PreTestAction,
                       CharTable,
                       TestResult)


class Grammar:
    def __init__(self, logger, grammar_path, seed):
        self.__logger: Logger = logger
        self.__nonterminals: dict[NonTerminal] = {}
        self.__char_tables: dict[CharTable] = {}
        self.__mutations: dict[Mutation] = {}
        self.__pre_tests: dict[PreTest] = {}
        self.__seed = seed
        self.__logger.info("Reading grammar-file")
        self.__laplace_alpha = 0.1
        self.__laplace_beta = 0.1
        self.__success_boost = 1.0
        file = open(grammar_path, "r")
        try:
            json_dict = json.loads(file.read())
        except Exception as e:
            self.__logger.critical("Error reading grammar-json. Error:",
                                   str(e))
            exit(-1)
        self.__parse_json(json_dict)
        error_message = self.__check_grammar()
        if error_message is not None:
            self.__parser_error(f"grammar check failed - {error_message}")
        self.__logger.info("Grammar check passed")

    def get_nonterminal(self, nonterminal) -> NonTerminal:
        return self.__nonterminals[nonterminal]

    def get_char_table(self, char_table) -> CharTable:
        return self.__char_tables[char_table]

    def get_mutation(self, mutation) -> Mutation:
        return self.__mutations[mutation]

    def get_pre_test(self, pre_test) -> PreTest:
        return self.__pre_tests[pre_test]

    def get_all_pre_tests(self):
        return self.__pre_tests.items()

    def get_all_char_tables(self):
        return self.__char_tables.items()

    def is_header(self, nonterminal) -> bool:
        return isinstance(self.__nonterminals[nonterminal], Header)
    
    def report_pre_test_result(self, pre_test_key, result: TestResult):
        self.__pre_tests[pre_test_key].result = result

    def apply_pre_test_actions(self):
        # At first apply all drops, then all raises/lowerings
        for target_func in [self.__apply_pre_tests_drops,
                            self.__apply_pre_test_raises_lowerings]:
            for key, pre_test in self.__pre_tests.items():
                if not isinstance(pre_test, PreTest):
                    raise TypeError(f"Expected Pretest but got {type(pre_test)}")
                for result, actions in pre_test.influence.items():
                    match result:
                        case "accepted":
                            if pre_test.result != TestResult.ACCEPTED:
                                continue
                        case "modified":
                            if pre_test.result != TestResult.MODIFIED:
                                continue
                        case "timeout":
                            if pre_test.result != TestResult.TIMEOUT:
                                continue
                        case "rejected":
                            if pre_test.result != TestResult.REJECTED:
                                continue
                        case _:
                            raise ValueError(f"unkown result in PreTest: {result}")
                    target_func(key, actions)

    def __apply_pre_tests_drops(self, pre_test_key, actions):
        for action, influence in actions.items():
            if action == "drop":
                for pre_test_action in influence:
                    if not isinstance(pre_test_action, PreTestAction):
                        raise TypeError(f"Expected PreTestAction, got {type(pre_test_action)}")
                    self.__pre_test_action_drop(pre_test_action)

    def __apply_pre_test_raises_lowerings(self, pre_test_key, actions):        
        to_be_recalculated = {}
        for action, influence in actions.items():
            target_func = None
            match action:
                case "drop":
                    continue
                case "raise":
                    target_func = self.__pre_test_action_raise
                case "lower":
                    target_func = self.__pre_test_action_lower
                case _:
                    raise ValueError(f"Unkown action in pretest {pre_test_key}: {action}")
            for pre_test_action in influence:
                if not isinstance(pre_test_action, PreTestAction):
                    raise TypeError(f"Expected PreTestAction, got {type(pre_test_action)}")
                # Add nonterminals that must be recalculated
                key_ignored_list = target_func(pre_test_action)
                for key_ignore_tuple in key_ignored_list:
                    key = key_ignore_tuple[0]
                    ignored = key_ignore_tuple[1]
                    if key not in to_be_recalculated:
                        to_be_recalculated[key] = ignored
                    else:
                        for ignored_index in ignored:
                            if ignored_index not in to_be_recalculated[key]:
                                to_be_recalculated[key].append(ignored_index)

        # Recalculate probabilities for raised/lowered
        for nonterminal_key, ignored_indicies in to_be_recalculated.items():
            self.__recalculate_probabilites((nonterminal_key, ignored_indicies))

    def __recalculate_probabilites(self, nonterminal_ignored: tuple[str, list[int] | None]):
        nonterminal = self.get_nonterminal(nonterminal_ignored[0])
        if nonterminal_ignored[1]:
            ignored = nonterminal_ignored[1]
        else:
            ignored = []
        assert isinstance(nonterminal, NonTerminal), f"Expected NonTerminal, got {type(nonterminal)}"
        added_probabilites = sum(nonterminal.probabilities)
        num_considered_probabilities = len(nonterminal.probabilities) - len(ignored)
        remaining = 1.0 - added_probabilites
        for i, _ in enumerate(nonterminal.probabilities):
            if i not in ignored:
                nonterminal.probabilities[i] += remaining / num_considered_probabilities

    def __pre_test_action_drop(self, pt_action: PreTestAction):
        to_be_recalculated = []
        if pt_action.derivative is not None:
            target = self.get_nonterminal(pt_action.nonterminal)
            if not isinstance(target, NonTerminal):
                raise TypeError(f"Expected NonTerminal but got {type(target)}")
            if not isinstance(pt_action.derivative, int):
                raise TypeError(f"Expected int but got {type(pt_action.derivative)}")
            target.derivatives.pop(pt_action.derivative)
            target.probabilities.pop(pt_action.derivative)
            to_be_recalculated.append(target)
        else:
            for _, nonterminal in self.__nonterminals.items():
                if not isinstance(nonterminal, NonTerminal):
                    if isinstance(nonterminal, (Header, Data)):
                        continue
                    else:
                        raise TypeError(f"Expected Header or NonTerminal but got {type(nonterminal)}")
                to_be_deleted = []
                for derivative in nonterminal.derivatives:
                    if derivative and pt_action.nonterminal in derivative:
                        to_be_deleted.append(derivative)
                        if nonterminal not in to_be_recalculated:
                            to_be_recalculated.append(nonterminal)
                for derivative in to_be_deleted:
                    index = nonterminal.derivatives.index(derivative)
                    nonterminal.derivatives.pop(index)
                    nonterminal.probabilities.pop(index)
        for nonterminal in to_be_recalculated:
            self.__recalculate_probabilites((nonterminal.name, None))

    def __pre_test_action_raise(self, pt_action: PreTestAction, lower = False):
        key_ignored_list = []
        if pt_action.derivative is not None:
            nonterminal = self.get_nonterminal(pt_action.nonterminal)
            if not isinstance(nonterminal, NonTerminal):
                raise TypeError(f"Expected NonTerminal but got {type(nonterminal)}")
            if not isinstance(pt_action.derivative, int):
                raise TypeError(f"Expected int but got {type(pt_action.derivative)}")
            probability = nonterminal.probabilities[pt_action.derivative]
            new_probability = None
            if lower:
                new_probability = probability * (1.0 - pt_action.factor)
            else:
                new_probability = probability + ((1.0 - probability) * pt_action.factor)
            nonterminal.probabilities[pt_action.derivative] = new_probability
            key_ignored_list.append((pt_action.nonterminal, [pt_action.derivative]))
        else:
            for _, nonterminal in self.__nonterminals.items():
                if not isinstance(nonterminal, NonTerminal):
                    if isinstance(nonterminal, (Header, Data)):
                        continue
                    else:
                        raise TypeError(f"Expected Header or NonTerminal but got {type(nonterminal)}")
                to_be_changed = []
                for index, derivative in enumerate(nonterminal.derivatives):
                    if derivative and pt_action.nonterminal in derivative:
                        to_be_changed.append(index)
                for index in to_be_changed:
                    probability = nonterminal.probabilities[index]
                    new_probability = None
                    if lower:
                        new_probability = probability * (1.0 - pt_action.factor)
                    else:
                        new_probability = probability + ((1.0 - probability) * pt_action.factor)
                    nonterminal.probabilities[index] = new_probability
                if to_be_changed != []:
                    key_ignored_list.append((nonterminal.name, to_be_changed))
        return key_ignored_list

    def __pre_test_action_lower(self, pt_action: PreTestAction):
        return self.__pre_test_action_raise(pt_action, True)
    
    def __parse_json(self, json_dict):
        for key, group in json_dict.items():
            match key:
                case "pre-tests":
                    for test_key, test in group.items():
                        self.__parse_pre_test(test_key, test)
                case "nonterminals":
                    for nonterminal_key, nonterminal in group.items():
                        self.__parse_nonterminal(nonterminal_key, nonterminal)
                case "headers":
                    for header_key, header in group.items():
                        self.__parse_header(header_key, header)
                case "data":
                    for data_key, data in group.items():
                        self.__parse_data(data_key, data)
                case "char-tables":
                    for char_table_key, char_table in group.items():
                        self.__parse_char_table(char_table_key, char_table)
                case "mutations":
                    for mutation_key, mutation in group.items():
                        self.__parse_mutation(mutation_key, mutation)
                case _:
                    self.__parser_error(f"key '{str(key)}' unkown")

    def __parse_char_table(self, name, dict):
        """
        Parses char tables from grammar-file.

        In the grammar-file, chars can be represented as strings or hex-chars.
        Hex-chars start with '0x' and two digits follow.

        Each character is stored three times as a tuple containing the char and
        a number out of [-1, 0, 1] (for example ('0x20', -1)). Each number
        represents the position of the character in the string, where -1
        represents a post-, 0 pre-, and 1 infix-position.
        """
        illegal_in = dict.get("illegal-in")
        if illegal_in is not None:
            if illegal_in not in ["header-name", "header-value"]:
                self.__parser_error(f"""char-table '{name}':
                                    unkown illegal-in value""")
        table = dict.get("table")
        if table is None or not isinstance(table, list):
            self.__parser_error(f"""char-table '{name}':
                                table missing or wrong type""")
        char_table = []
        for char in table:
            if char.startswith("0x"):
                char_table.append(chr(int(char, 16)).encode())
            else:
                char_table.append(char.encode())
        table_length = len(char_table)
        init_probability = 1 / (table_length * 3)
        options = []
        test_results = []
        for char in char_table:
            options.append((char, -1))  # Postfix
            options.append((char, 0))   # Prefix
            options.append((char, 1))   # Infix
            for i in range(3):
                test_results.append([0, 0])
        probabilities = [init_probability] * len(options)
        self.__char_tables[name] = CharTable(options,
                                             test_results,
                                             probabilities,
                                             illegal_in,
                                             self.__laplace_alpha,
                                             self.__laplace_beta,
                                             self.__success_boost)

    def __parse_header(self, name, dict):
        name_terminal = self.__parse_terminal(dict["name-field"])
        value_terminal = self.__parse_terminal(dict["value-field"])
        header = Header(name, name_terminal, value_terminal)
        self.__nonterminals[name] = header

    def __parse_data(self, name, dict):
        load = dict.get("load")
        if load is None:
            load = b""
        else:
            load = load.encode()
        data = Data(load)
        self.__nonterminals[name] = data

    def __parse_nonterminal(self, name, dict):
        # Parse derivatives
        raw_derivatives = dict["derivatives"]
        derivatives = []
        for raw_derivative in raw_derivatives:
            derivatives.extend([self.__parse_brackets(raw_derivative)])
        # Parse probabilities
        probabilities = self.__parse_probabilities(dict.get("probabilities"),
                                                   len(derivatives))
        # Parse permutationable
        permutationable = dict.get("permutationable")
        if permutationable is not None and not isinstance(permutationable,
                                                          bool):
            self.__parser_error(f"{name} has unkown permutationable attribute")
        if permutationable is None:
            permutationable = False
        # Parse illegal
        illegal = self.__parse_illegal(dict)
        # Add to dict of all nonterminals
        self.__nonterminals[name] = NonTerminal(name,
                                                derivatives,
                                                probabilities,
                                                permutationable,
                                                illegal)

    def __parse_illegal(self, dict):
        illegal = dict.get("illegal")
        if illegal is None:
            illegal = False
        return illegal

    def __parse_probabilities(self, json_probabilities, num_derivatives):
        if num_derivatives <= 1:
            return [1]
        if json_probabilities == "equal" or json_probabilities is None:
            probability = 1 / num_derivatives
            probabilities = [probability] * num_derivatives
        else:
            probabilities = json_probabilities
        return probabilities

    def __parse_mutation(self, name, dict):
        mutation = None
        action = dict.get("action")
        match action:
            case "insert-char":
                mutation = InsertChar(name,
                                      self,
                                      dict.get("char-table"),
                                      dict.get("char-position"),
                                      dict.get("quantity"),
                                      self.__seed)
            case "delete-char":
                mutation = DeleteChar(name,
                                      dict.get("char-position"),
                                      dict.get("quantity"),
                                      self.__seed)
            case "fill-until-max":
                mutation = FillUntilMax(name,
                                        self,
                                        dict.get("char-table"),
                                        dict.get("char-position"),
                                        dict.get("offset"),
                                        self.__seed)
            case "add-max":
                mutation = AddMax(name,
                                        self,
                                        dict.get("char-table"),
                                        dict.get("char-position"),
                                        dict.get("offset"),
                                        self.__seed)
            case "replace-with-uppercase":
                mutation = ReplaceWithUppercase(name,
                                                dict.get("quantity"),
                                                self.__seed)
            case _:
                self.__parser_error(f"""{name} has unkown mutation action
                                    '{action}'""")
        self.__mutations[name] = mutation

    def __parse_pre_test(self, name, test):
        # Parse sequence
        sequence_str = test.get("sequence")
        if sequence_str is None or not isinstance(sequence_str, str):
            self.__parser_error(f"""pre-test {name} has headers missing or is
                                not a string""")
        sequence = self.__parse_brackets(sequence_str)
        # Parse influences
        influences = {}
        influences_dict = test.get("influence")
        if influences_dict is None or not isinstance(influences_dict, dict):
            self.__parser_error(f"""pre-test {name} has influce missing or is
                                not a dict""")
        for influence_key, actions_dict in influences_dict.items():
            if influence_key not in ["if-accepted",
                                     "if-modified",
                                     "if-timeout",
                                     "if-rejected"]:
                self.__parser_error(f"""pre-test {name} has unkown condition
                                    '{influence_key}'""")
            case = influence_key.removeprefix("if-")
            if actions_dict is not None and not isinstance(actions_dict, dict):
                self.__parser_error(f"""pre-test {name}, {influence_key},
                                        must be a dict""")
            if actions_dict is None:
                influences[case] = None
            else:
                influences[case] = {}
                actions = {}
                for action_key, targets in actions_dict.items():
                    if not isinstance(targets, list):
                        self.__parser_error(f"""pre-test {name},
                                            {influence_key}, {action_key} must
                                            be a list""")
                    if action_key not in ["drop", "raise", "lower"]:
                        self.__parser_error(f"pre-test {name}, " \
                                            f"{influence_key} has unkown " \
                                            f"action '{action_key}'")
                    influences[case][action_key] = \
                    self.__parse_pre_test_actions(name, action_key, targets)
        self.__pre_tests[name] = PreTest(sequence, influences, None)
                        

    def __parse_pre_test_actions(self, name, action, targets):
        actions = []
        for target in targets:
            if not isinstance(target, list):
                self.__parser_error("influence-actions must be lists (check" \
                                    f" {name})")
            nonterminal = None
            derivative = None
            factor = None
            if action == "drop":
                nonterminal, \
                derivative = self.__parse_pre_test_actions_target(name, target)
            elif action == "raise" or action == "lower":
                if not isinstance(target[0], list):
                    self.__parser_error(f"""pre-test {name} has invalid
                                        influence-action""")
                nonterminal, \
                derivative = self.__parse_pre_test_actions_target(name,
                                                                  target[0])
                if not isinstance(target[1], float):
                    self.__parser_error(f"""pre-test {name}, 'raise' and
                                        'lower' must include a factor""")
                if not (0 <= target[1] <= 1.0):
                    self.__parser_error(f"""pre-test {name}, has a factor that
                                        is smaller than 0 or greater than 1""")
                factor = target[1]
            else:
                self.__parser_error(f"pre-test {name} has unkown action: {action}")

            actions.append(PreTestAction(nonterminal, derivative, factor))
        return actions


    def __parse_pre_test_actions_target(self, name, target_list):
        nonterminal = self.__parse_brackets(target_list[0])
        if len(nonterminal) != 1:
            self.__parser_error(f"""pre-test {name} has an action that targets
                                more than one nonterminal""")
        if len(target_list) == 1:
            return nonterminal[0], None
        if not isinstance(target_list[1], int) and target_list[1] is not None:
            self.__parser_error(f"""pre-test {name} tries to influence
                                {nonterminal[0]}, but index isn't an int""")
        return nonterminal[0], target_list[1]

    def __parse_brackets(self, string):
        if string is None:
            return None
        return re.findall(r"<(.*?)>", string)

    def __parse_terminal(self, dict):
        terminals_str = dict["terminals"]
        terminals = [terminal.encode() for terminal in terminals_str]
        # Parse mutations
        raw_mutations = dict.get("mutations")
        if raw_mutations is None:
            mutations = None
        else:
            mutations = []
            if raw_mutations is not None:
                for raw_mutation in raw_mutations:
                    mutations.extend([self.__parse_brackets(raw_mutation)])
        # Parse terminals-probabilities
        terminals_probabilities = self.__parse_probabilities(
            dict.get("terminals-probabilities"),
            len(terminals))
        # Parse mutations-probabilities
        if mutations is None:
            mutations_probabilities = None
        else:
            mutations_probabilities = self.__parse_probabilities(
                dict.get("mutations-probabilities"),
                len(mutations))
        is_illegal = self.__parse_illegal(dict)
        return Terminal(terminals,
                        terminals_probabilities,
                        mutations,
                        mutations_probabilities,
                        is_illegal)

    def __check_grammar(self) -> str | None:
        # Check self.__nonterminals
        for nonterminal_key, nonterminal in self.__nonterminals.items():
            if isinstance(nonterminal, NonTerminal):
                func = self.__check_nonterminal
            elif isinstance(nonterminal, Header):
                func = self.__check_header
            elif isinstance(nonterminal, Data):
                func = self.__check_data
            else:
                raise TypeError
            error_msg = func(nonterminal)
            if error_msg is not None:
                return error_msg
        # Check self.__mutations
        for mutation_key, mutation in self.__mutations.items():
            error_msg = self.__check_mutation(mutation_key, mutation)
            if error_msg is not None:
                return error_msg
        # Check self.__pre_tests
        for pre_test_key, pre_test in self.__pre_tests.items():
            error_msg = self.__check_pre_test(pre_test_key, pre_test)
            if error_msg is not None:
                return error_msg
        return None

    def __check_pre_test(self, name, pre_test: PreTest):
        if not isinstance(pre_test.sequence, list):
            raise TypeError
        for header in pre_test.sequence:
            if not isinstance(header, str):
                raise TypeError
            if not header in self.__nonterminals.keys():
                return f"pre-test '{name}' has unkown header '{header}'"
            if not isinstance(self.__nonterminals[header], (Header, Data)):
                return f"pre-test '{name}' - '{header}' is not definded"
        if pre_test.influence is {}:
            return f"pre-test '{name}' has no influence defined"
        for case, action_dict in pre_test.influence.items():
            if action_dict is None:
                continue
            if not isinstance(action_dict, dict):
                raise TypeError
            if case not in ["accepted", "rejected", "timeout", "modified"]:
                return f"pre-test '{name}' unkown case '{case}'"
            for action, action_list in action_dict.items():
                if action not in ["drop", "raise", "lower"]:
                    return f"pre-test '{name}' unkown action '{action}'"
                if action_list is None or not isinstance(action_list, list):
                    raise TypeError
                for pre_test_action in action_list:
                    error_msg = self.__check_pre_test_action(name,
                                                             action,
                                                             pre_test_action)
                    if error_msg is not None:
                        return error_msg
        return None

    def __check_pre_test_action(self, name, action, pre_test_action):
        if pre_test_action.nonterminal is None:
            raise TypeError
        if not isinstance(pre_test_action.nonterminal, str):
            raise TypeError
        nonterminal = self.__nonterminals.get(pre_test_action.nonterminal)
        if nonterminal is None:
            return f"pre-test '{name}' has action that tries to influence" \
                   "non-exsistent nonterminal"
        if isinstance(nonterminal, Header):
            if pre_test_action.derivative is not None:
                return f"pre-test '{name}' has action that tries to influence" \
                   "header but index for derivative is specified"
        elif isinstance(nonterminal, NonTerminal):
            if pre_test_action.derivative is not None:
                if not isinstance(pre_test_action.derivative, int):
                     return f"pre-test '{name}' has action that has an " \
                     "index which is not an int"
                if len(nonterminal.derivatives) <= pre_test_action.derivative:
                    return f"pre-test '{name}' has action that tries to " \
                    "influence nonterminal with specified derivative index " \
                    "out of range"
                if pre_test_action.derivative < 0:
                    return f"pre-test '{name}' has action with negative index"
        if action != "drop" and not isinstance(pre_test_action.factor, float):
            return f"pre-test '{name}' with action '{action}' rquires float " \
                   "factor"
        return None

    def __check_mutation(self, name, mutation: Mutation):
        check_char_table = True
        check_char_position = True
        check_quantity = True
        check_grammar = False
        if isinstance(mutation, InsertChar):
            check_grammar = True
        elif isinstance(mutation, FillUntilMax):
            if mutation._quantity is not None:
                raise TypeError
            check_grammar = True
            check_quantity = False
        elif isinstance(mutation, ReplaceWithUppercase):
            check_char_table = False
            check_char_position = False
        elif isinstance(mutation, DeleteChar):
            check_char_table = False
        else:
            raise TypeError
        if check_char_table:
            if mutation._char_table is None:
                return f"{name}: missing char table"
            if not isinstance(mutation._char_table, str):
                raise TypeError
            if mutation._char_table not in self.__char_tables.keys():
                return f"{name}: char-table unknown"
            if not isinstance(self.__char_tables[mutation._char_table],
                              CharTable):
                raise TypeError
        if check_char_position:
            allowed_char_positions = ["all", "prefix", "postfix", "infix"]
            if not isinstance(mutation._char_position, str):
                raise TypeError
            if mutation._char_position not in allowed_char_positions:
                return f"{name}: unkown chr position {mutation._char_position}"
        if check_grammar:
            if not isinstance(mutation._grammar, Grammar):
                print(mutation)
                print(type(mutation._grammar))
                raise TypeError
        if check_quantity:
            if not isinstance(mutation, (FillUntilMax, AddMax)):
                if not isinstance(mutation._quantity, int):
                    if mutation._quantity is None:
                            return f"{name}: missing quantity"
                    return f"{name}: quantity must be of type int"
                if mutation._quantity <= 0:
                    return f"{name}: quantity must greater than 0"
        return None

    def __check_data(self, data: Data):
        if not isinstance(data.load, bytes):
            raise TypeError
        if not isinstance(data.is_illegal, bool):
            raise TypeError
        return None

    def __check_header(self, header: Header):
        if not isinstance(header.name_terminal, Terminal):
            raise TypeError
        error_msg = self.__check_terminal(header.name, header.name_terminal)
        if error_msg is not None:
            return error_msg
        return self.__check_terminal(header.name, header.value_terminal)

    def __check_terminal(self, name, terminal: Terminal):
        if not isinstance(terminal.terminals, list):
            if terminal.terminals is None:
                return f"{name}: header must have at least one terminal"
            raise TypeError
        if not isinstance(terminal.terminals_probabilities, list):
            raise TypeError
        if not isinstance(terminal.is_illegal, bool):
            raise TypeError
        if not isinstance(terminal.mutations, list):
            if terminal.mutations is None:
                if terminal.mutations_probabilities is not None:
                    return f"{name}: has no mutations but probabilities for it"
            else:
                raise TypeError
        else:
            for mutation_sequence in terminal.mutations:
                if not isinstance(mutation_sequence, list):
                    if mutation_sequence is None:
                        continue
                    raise TypeError
                for mutation in mutation_sequence:
                    if mutation not in self.__mutations.keys():
                        return f"{name}: mutation '{mutation}' undefined"
        if not isinstance(terminal.mutations_probabilities, list):
            if terminal.mutations_probabilities is not None:
                raise TypeError
        if not sum(terminal.terminals_probabilities) == 1:
            return f"{name}: terminals-probabilities do not add up to 1"
        if len(terminal.terminals) != len(terminal.terminals_probabilities):
            return f"{name}: number of terminals does not match number of " + \
                "terminals-probabilities"
        for string in terminal.terminals:
            if not isinstance(string, bytes):
                raise TypeError
            if "<" in string.decode() or ">" in string.decode():
                replacements = self.__parse_brackets(string.decode())
                if replacements is None:
                    return f"{name}: most likely missing '<' or '>'"
                allowed_replacements = ["authority", "path"]
                for replacement in replacements:
                    if replacement not in allowed_replacements:
                        return f"{name}: <{replacement}> is unkown"

        # Check if mutations-probabilities are given
        if terminal.mutations_probabilities is None:
            return None
        if not sum(terminal.mutations_probabilities) == 1:
            return f"{name}: mutations-probabilities do not add up to 1"
        if len(terminal.mutations) != len(terminal.mutations_probabilities):
            return f"{name}: number of mutations does not match number of " + \
                "mutations-probabilities"
        return None

    def __check_nonterminal(self, nonterminal: NonTerminal):
        if not isinstance(nonterminal.derivatives, list):
            raise TypeError
        if not isinstance(nonterminal.probabilities, list):
            raise TypeError
        if not isinstance(nonterminal.permutationable, bool):
            raise TypeError
        if not isinstance(nonterminal.is_illegal, bool):
            raise TypeError
        if not len(nonterminal.derivatives) == len(nonterminal.probabilities):
            return f"{nonterminal.name}: number of derivatives does not" \
                "match number of probabilities"
        for derivative in nonterminal.derivatives:
            if derivative is None:
                continue
            elif isinstance(derivative, list):
                for extended_item in derivative:
                    if not isinstance(extended_item, str):
                        raise TypeError
                    if extended_item not in self.__nonterminals.keys():
                        return "NonTerminal " + extended_item + " is missing"
            else:
                raise TypeError
        if not sum(nonterminal.probabilities) == 1:
            return f"{nonterminal.name}: probabilities do not add up to 1"
        return None
    
    def __parser_error(self, message: str):
        self.__logger.critical(f"Error parsing grammar: {message}")
        exit(-1)
