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

class Label:
    """Additional data used to encrypt the entry table."""

    def to_bytes(self) -> bytes:
        """Convert to bytes.

        Returns:
            bytes
        """
    @staticmethod
    def random() -> Label:
        """Initialize a random label.

        Returns:
            Label
        """
    @staticmethod
    def from_bytes(label_bytes: bytes) -> Label:
        """Load from bytes.

        Args:
            label_bytes (bytes)

        Returns:
            Label
        """
    @staticmethod
    def from_string(label_str: str) -> Label:
        """Load from a string.

        Args:
            label_str (str)

        Returns:
            Label
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
    """Callback structure used to instantiate a Findex backend."""

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
    def new_with_sqlite_backend(
        key: Key, label: Label, entry_path: str, chain_path: str
    ) -> Findex:
        """Instantiate a new Findex instance using an SQLite backend.

        Returns:
            Findex
        """
    @staticmethod
    def new_with_redis_backend(
        key: Key, label: Label, entry_url: str, chain_url: str
    ) -> Findex:
        """Instantiate a new Findex instance using Redis backend.

        Returns:
            Findex
        """
    @staticmethod
    def new_with_rest_backend(key: Key, label: Label, token: str, url: str) -> Findex:
        """Instantiate a new Findex instance using REST backend.

        Returns:
            Findex
        """
    @staticmethod
    def new_with_custom_backend(
        key: Key,
        label: Label,
        entry_callbacks: PythonCallbacks,
        chain_callbacks: PythonCallbacks,
    ) -> Findex:
        """Instantiate a new Findex instance using custom backend.

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
        new_label: Label,
        num_reindexing_before_full_set: int,
        filter: Optional[Callable] = None,
    ) -> None:
        """Compact the index. Encrypts the compacted index using the new key
        and new label.
        """
