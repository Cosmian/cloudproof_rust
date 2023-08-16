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

class MasterKey:
    """Input key used to derive Findex keys."""

    def to_bytes(self) -> bytes:
        """Convert to bytes.

        Returns:
            bytes
        """
    @staticmethod
    def random() -> MasterKey:
        """Initialize a random key.

        Returns:
            MasterKey
        """
    @staticmethod
    def from_bytes(key_bytes: bytes) -> MasterKey:
        """Load from bytes.

        Args:
            key_bytes (bytes)

        Returns:
            MasterKey
        """

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

class InternalFindex:
    """This is an internal class. See `cloudproof_py.findex.Findex` abstract class instead."""

    def set_upsert_callbacks(
        self,
        fetch_entry_table: Callable,
        upsert_entry_table: Callable,
        insert_chain_table: Callable,
    ) -> None: ...
    def set_search_callbacks(
        self,
        fetch_entry_table: Callable,
        fetch_chain_table: Callable,
    ) -> None: ...
    def set_compact_callbacks(
        self,
        fetch_entry_table: Callable,
        fetch_chain_table: Callable,
        update_lines: Callable,
        list_removed_locations: Callable,
        fetch_all_entry_table_uids: Callable,
    ) -> None: ...
    def upsert_wrapper(
        self,
        master_key: MasterKey,
        label: Label,
        additions: IndexedValuesAndKeywords,
        deletions: IndexedValuesAndKeywords,
    ) -> Set[Keyword]: ...
    def search_wrapper(
        self,
        msk: MasterKey,
        label: Label,
        keywords: Sequence[Union[Keyword, str]],
        progress_callback: Optional[Callable] = None,
    ) -> SearchResults: ...
    def compact_wrapper(
        self,
        master_key: MasterKey,
        new_master_key: MasterKey,
        new_label: Label,
        num_reindexing_before_full_set: int,
    ) -> None: ...
