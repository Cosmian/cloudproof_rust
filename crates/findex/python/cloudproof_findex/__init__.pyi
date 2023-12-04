from typing import Callable, Dict, List, Optional, Sequence, Set, Union

IndexedValuesAndKeywords = Dict[Union[Location, Keyword], Sequence[Union[str, Keyword]]]
SearchResults = Dict[Union[Keyword, str, bytes], List[Location]]
ProgressResults = Dict[Union[Keyword, str, bytes], List[Union[Location, Keyword]]]

class Keyword:
    """A `Keyword` is a byte vector used to index other values."""

    @staticmethod
    def from_string(val: str) -> Keyword:
        """Create `Keyword` from string.

        Args:
            str (str)

        Returns:
            Keyword
        """
    @staticmethod
    def from_bytes(val: bytes) -> Keyword:
        """Create `Keyword` from bytes.

        Args:
            val (bytes)

        Returns:
            Keyword
        """
    @staticmethod
    def from_int(val: int) -> Keyword:
        """Create `Keyword` from int.

        Args:
            val (int)

        Returns:
            Keyword
        """
    def __str__(self) -> str:
        """Convert `Keyword` to string.

        Returns:
            str
        """
    def __int__(self) -> int:
        """Convert `Keyword` to int.

        Returns:
            int
        """
    def __bytes__(self) -> bytes:
        """Convert `Keyword` to bytes.

        Returns:
            bytes
        """

class Location:
    """A `Location` is a byte vector used to index other values."""

    @staticmethod
    def from_string(val: str) -> Location:
        """Create `Location` from string.

        Args:
            str (str)

        Returns:
            Location
        """
    @staticmethod
    def from_bytes(val: bytes) -> Location:
        """Create `Location` from bytes.

        Args:
            val (bytes)

        Returns:
            Location
        """
    @staticmethod
    def from_int(val: int) -> Location:
        """Create `Location` from int.

        Args:
            val (int)

        Returns:
            Location
        """
    def __str__(self) -> str:
        """Convert `Location` to string.

        Returns:
            str
        """
    def __int__(self) -> int:
        """Convert `Location` to int.

        Returns:
            int
        """
    def __bytes__(self) -> bytes:
        """Convert `Location` to bytes.

        Returns:
            bytes
        """

class Key:
    """Input key used to derive Findex keys."""

    def to_bytes(self) -> bytes:
        """Convert to bytes.

        Returns:
            bytes
        """
    @staticmethod
    def random() -> Key:
        """Initialize a random key.

        Returns:
            Key
        """
    @staticmethod
    def from_bytes(key_bytes: bytes) -> Key:
        """Load from bytes.

        Args:
            key_bytes (bytes)

        Returns:
            Key
        """

class PythonCallbacks:
    """Callback structure used to instantiate a Findex DB interface."""

    @staticmethod
    def new() -> PythonCallbacks:
        """Initialize a new callback structure."""
    def set_fetch(self, callback: object):
        """Sets the fetch callback."""
    def set_upsert(self, callback: object):
        """Sets the upsert callback."""
    def set_insert(self, callback: object):
        """Sets the insert callback."""
    def set_delete(self, callback: object):
        """Sets the delete callback."""
    def set_dump_tokens(self, callback: object):
        """Sets the dump_tokens callback."""

class AuthorizationToken:
    @staticmethod
    def new(
        index_id: str,
        findex_key: Key,
        fetch_entries_key: Key,
        fetch_chains_key: Key,
        upsert_entries_key: Key,
        insert_chains_key: Key,
    ) -> AuthorizationToken:
        """Create a new token from the given elements.

        Returns:
            Authorization token"""
    @staticmethod
    def random(index: str) -> AuthorizationToken:
        """Generate a new random authorization token.

        Returns:
            AuthorizationToken
        """
    def generate_reduced_token_string(self, is_read: bool, is_write: bool) -> str:
        """Generate a token string with the given reduced permissions.

        Returns:
            str
        """
    def __str__(self) -> str:
        """Convert the authorization token to string.

        Returns:
            str
        """

class Findex:
    @staticmethod
    def new_with_sqlite_interface(
        key: Key, label: str, entry_path: str, chain_path: Optional[str]=None
    ) -> Findex:
        """Instantiate a new Findex instance using an SQLite interface.

        Returns:
            Findex
        """
    @staticmethod
    def new_with_redis_interface(
        key: Key, label: str, entry_url: str, chain_url: Optional[str]=None
    ) -> Findex:
        """Instantiate a new Findex instance using a Redis interface.

        Returns:
            Findex
        """
    @staticmethod
    def new_with_rest_interface(label: str, token: str, entry_url: str,
                                chain_url: Optional[str]=None) -> Findex:
        """Instantiate a new Findex instance using a REST interface.

        Returns:
            Findex
        """
    @staticmethod
    def new_with_custom_interface(
        key: Key,
        label: str,
        entry_callbacks: PythonCallbacks,
        chain_callbacks: Optional[PythonCallbacks]=None,
    ) -> Findex:
        """Instantiate a new Findex instance using a custom interface.

        Returns:
            Findex
        """
    def add(
        self,
        additions: IndexedValuesAndKeywords,
    ) -> Set[Keyword]:
        """Index the given values for the associated keywords.

        Returns:
            The set of new keywords."""
    def delete(
        self,
        deletions: IndexedValuesAndKeywords,
    ) -> Set[Keyword]:
        """Remove the given values for the associated keywords from the index.

        Returns:
            The set of new keywords."""
    def search(
        self,
        keywords: Sequence[Union[Keyword, str]],
        interrupt: Optional[Callable] = None,
    ) -> SearchResults:
        """Search for the given keywords in the index.

        Returns:
            The values indexed for those tokens."""
    def compact(
        self,
        new_key: Key,
        new_label: str,
        compacting_rate: float,
        data_filter: Optional[Callable] = None,
    ) -> None:
        """Compact the index. Encrypts the compacted index using the new key
        and new label.
        """
