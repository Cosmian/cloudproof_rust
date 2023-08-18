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

class FindexCloud:
    """Ready to use Findex with a backend powered by Cosmian."""

    @staticmethod
    def upsert(
        token: str,
        label: Label,
        additions: IndexedValuesAndKeywords,
        deletions: IndexedValuesAndKeywords,
        base_url: Optional[str] = None,
    ) -> Set[Keyword]:
        """Upserts the given relations between `IndexedValue` and `Keyword` into Findex tables.

        Args:
            token (str): Findex token.
            label (Label): label used to allow versioning.
            additions (Dict[Location | Keyword, List[Keyword | str]]):
                map of `IndexedValue` to a list of `Keyword`.
            deletions (Dict[Location | Keyword, List[Keyword | str]]):
                map of `IndexedValue` to a list of `Keyword`.
            base_url (str, optional): url of Findex backend.
        """
    @staticmethod
    def search(
        token: str,
        label: Label,
        keywords: Sequence[Union[Keyword, str]],
        base_url: Optional[str] = None,
    ) -> SearchResults:
        """Recursively search Findex graphs for `Locations` corresponding to the given `Keyword`.

        Args:
            token (str): Findex token.
            label (Label): public label used in keyword hashing.
            keywords (List[Keyword | str]): keywords to search using Findex.
            base_url (str, optional): url of Findex backend.

        Returns:
            Dict[Keyword, List[Location]]: `Locations` found by `Keyword`
        """
    @staticmethod
    def derive_new_token(token: str, search: bool, index: bool) -> str: ...
    @staticmethod
    def generate_new_token(
        index_id: str,
        fetch_entries_seed: bytes,
        fetch_chains_seed: bytes,
        upsert_entries_seed: bytes,
        insert_chains_seed: bytes,
    ) -> str: ...

class Findex:
    @staticmethod
    def new_with_sqlite_backend(entry_path: str, chain_path: str) -> Findex: ...
    @staticmethod
    def new_with_redis_backend(entry_url: str, chain_url: str) -> Findex: ...
    @staticmethod
    def new_with_custom_backend(entry_callbacks: PythonCallbacks,
                                chain_callbacks: PythonCallbacks) -> Findex: ...
    def add(
        self,
        key: Key,
        label: Label,
        additions: IndexedValuesAndKeywords,
    ) -> Set[Keyword]: ...
    def delete(
        self,
        key: Key,
        label: Label,
        deletions: IndexedValuesAndKeywords,
    ) -> Set[Keyword]: ...
    def search(
        self,
        key: Key,
        label: Label,
        keywords: Sequence[Union[Keyword, str]],
        interrupt: Optional[Callable] = None,
    ) -> SearchResults: ...
    def compact(
        self,
        key: Key,
        new_key: Key,
        new_label: Label,
        num_reindexing_before_full_set: int,
    ) -> None: ...
