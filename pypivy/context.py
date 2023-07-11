from __future__ import annotations
from typing import Iterator
from pypivy.pivy_ctypes import *

from pypivy.errf import Errf
from pypivy.enums import *

class Context:
    """
    Represents a libpivy library context, the top-level structure which
    is used to track an "instance" of the entire library.
    """
    def __init__(self):
        self._handle = libpivy.piv_open()
    def __del__(self):
        if self._handle:
            libpivy.piv_close(self._handle)
        self._handle = None
    @property
    def valid(self) -> bool:
        """
        Returns True if the library context is valid and useable (i.e. has not
        been freed in C code)
        """
        if self._handle:
            return True
        else:
            return False
    def close(self):
        """
        Closes the library context, releasing all resources associated with it.
        Any tokens within the Context must not be presently in a transaction,
        or this function will abort the entire process.
        """
        libpivy.piv_close(self._handle)
        self._handle = None
    def establish(self, scope: SCardScope = SCardScope.USER) -> None:
        """
        Establishes a PCSC session for this library context. This is required
        before the context can be used to enumerate or find PIV tokens.

        :raises ServiceError: One of the PCSC "service not available"
            codes was returned indicating that a system daemon/service for PCSC
            is not running.
        :raises PCSCError: Any other PCSC error
        """
        err = libpivy.piv_establish_context(self._handle, scope.value)
        if err:
            raise Errf(err)
    def enumerate(self) -> Iterator[Token]:
        """
        Enumerates the set of all PIV tokens available.

        :raises PCSCContextError: a PCSC call failed in a way that indicates
            that the Context is no longer valid and must now be closed
        :raises PCSCError: a PCSC call failed in a way that is not retryable
        """
        ptr = c_void_p()
        err = libpivy.piv_enumerate(self._handle, byref(ptr))
        if err:
            raise Errf(err)
        return TokenSet(self, ptr)
    def find(self, guid_prefix_hex: str) -> Iterator[Token]:
        """
        Searches for a specific PIV token using its GUID, or a prefix fragment
        of the GUID.

        :param guid_prefix_hex: Hex string, e.g. "12ABC4"
        :raises DuplicateError: more than one PIV token matched the GUID
            prefix given (it is not unique)
        :raises NotFoundError: no token matching the GUID prefix could
            be found
        :raises PCSCContextError: a PCSC call failed in a way that indicates
            that the Context is no longer valid and must now be closed
        :raises PCSCError: a PCSC call failed in a way that is not retryable
        """
        ptr = c_void_p()
        guid = bytes.fromhex(guid_prefix_hex)
        err = libpivy.piv_find(self._handle, guid, len(guid), byref(ptr))
        if err:
            raise Errf(err)
        return TokenSet(self, ptr)

class TokenSet:
    """
    A set of tokens, returned via the enumerate() or find() methods of a libpivy
    Context. TokenSets can be iterated over to yield Token instances.

    :meta private:
    """
    def __init__(self, ctx: Context, ptr: c_void_p):
        self._ctx = ctx
        self._ptr = ptr
    def __del__(self):
        if self._ctx.valid:
            libpivy.piv_release(self._ptr)
        self._ptr = None
    @property
    def valid(self) -> bool:
        """
        Returns True if the token set is valid and useable (i.e. has not
        been freed in C code, and the Context it belongs to is also valid)
        """
        if not self._ctx.valid:
            return False
        if not self._ptr:
            return False
        return True
    def is_empty(self) -> bool:
        """
        Returns True if the TokenSet is empty and does not contain any Tokens.
        """
        if self._ptr:
            return False
        return True
    def __iter__(self) -> TokenIterator:
        return TokenIterator(self, self._ptr)

from pypivy.token import Token

class TokenIterator:
    """
    An iterator over a TokenSet.

    :meta private:
    """
    def __init__(self, set: TokenSet, ptr: c_void_p):
        self._set = set
        self._ptr = ptr
    def __next__(self) -> Token:
        ptr = self._ptr
        if ptr:
            self._ptr = libpivy.piv_token_next(ptr)
            return Token(set = self._set, ptr = ptr)
        else:
            raise StopIteration
