import asyncio
from logging import Logger
from utilities import TestState
from urllib.parse import urlparse
from qh3.h3.connection import QpackEncoderStreamError


MAX_HEADER_LENGTH = 2**32


class HeaderLengthTest:
    def __init__(self, logger: Logger, url: str, timeout: float):
        self.state = TestState.INIT
        self.result = None
        self.__timeout = timeout
        self._request_url = urlparse(url).netloc.encode()
        self._request_path = urlparse(url).path.encode()
        self._logger = logger
        self._l_bound = 8
        self._u_bound = 16
        self._c_length = self._u_bound

    async def run_test(self, http_request):
        self.state = TestState.RUNNING
        while self._u_bound <= MAX_HEADER_LENGTH:
            if self.__found_limit():
                self.state = TestState.FINISHED
                return
            recieved_ok = await self.__server_accepts_request(http_request)
            if recieved_ok:
                self._l_bound = self._c_length
                if self._c_length == self._u_bound:
                    self._u_bound = self._u_bound * 2
                    self._c_length = self._u_bound
                else:
                    self._c_length = \
                        int((self._u_bound - self._l_bound) / 2) \
                        + self._l_bound
            elif self.state == TestState.WAITING_FOR_NEW_CLIENT:
                self._u_bound = self._c_length
                self._c_length = int((self._u_bound - self._l_bound) / 2) \
                    + self._l_bound
                return
            elif self.state == TestState.FINISHED_WITH_ERROR:
                return
            elif self.state == TestState.RUNNING:
                continue
            else:
                raise TypeError

    async def __server_accepts_request(self, http_request):
        headers = self._get_headers()
        self._logger.info("Testing with " + str(self._c_length) + " bytes")
        try:
            resp = await asyncio.wait_for(http_request(headers=headers),
                                          timeout=self.__timeout)
            if resp[0].headers[0][1] == b'200':
                return True
            else:
                return False
        except (TimeoutError, Exception) as e:
            if isinstance(e, QpackEncoderStreamError) or \
               isinstance(e, TimeoutError):
                self.state = TestState.WAITING_FOR_NEW_CLIENT
                return False
            else:
                self._logger.critical("Error in length test: " + str(e))
                self._logger.info("Consider setting boundaries manually (-b)")
                TestState.FINISHED_WITH_ERROR
                return False

    def __found_limit(self) -> bool:
        if self._l_bound == self._c_length or \
           self._l_bound + 1 == self._u_bound:
            self.result = self._l_bound
            return True
        return False

    def _get_headers(self) -> list[tuple[bytearray, bytearray]]:
        raise NotImplementedError("Child must implement _getHeaders")


class HeaderNameLengthTest(HeaderLengthTest):
    def __init__(self, logger: Logger, url: str, timeout: float):
        super(HeaderNameLengthTest, self).__init__(logger, url, timeout)

    def _get_headers(self) -> list[tuple[bytearray, bytearray]]:
        return [(b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", self._request_url),
                (b":path", self._request_path),
                (b"user-agent", b"h-name-length-test-" +
                 str(self._c_length).encode()),
                (("x" * self._c_length).encode(), b"test")]


class HeaderValueLengthTest(HeaderLengthTest):
    def __init__(self, logger: Logger, url: str, timeout: float):
        super(HeaderValueLengthTest, self).__init__(logger, url, timeout)

    def _get_headers(self) -> list[tuple[bytearray, bytearray]]:
        return [(b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", self._request_url),
                (b":path", self._request_path),
                (b"user-agent", b"h-value-length-test-" +
                 str(self._c_length).encode()),
                (b"test", ("x" * self._c_length).encode())]
