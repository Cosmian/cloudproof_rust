# -*- coding: utf-8 -*-
import unittest
from typing import Dict, List, Set, Tuple, Sequence

from cloudproof_findex import (
    IndexedValuesAndKeywords,
    InternalFindex,
    Keyword,
    Label,
    Location,
    MasterKey,
    ProgressResults,
)


class TestStructures(unittest.TestCase):
    def test_location(self) -> None:
        # from string
        input_string = 'test location'
        loc_str = Location.from_string(input_string)
        # conversion
        self.assertEqual(str(loc_str), input_string)
        # comparison
        self.assertEqual(loc_str, input_string)
        self.assertNotEqual(loc_str, 'wrong str')
        # hash
        self.assertEqual(hash(loc_str), hash(input_string))

        # from int
        input_int = 2**51 - 1
        loc_int = Location.from_int(input_int)
        self.assertEqual(int(loc_int), input_int)
        # comparison
        self.assertEqual(loc_int, input_int)
        self.assertNotEqual(loc_int, 2**51 - 2)
        # hash not working for int

        # from bytes
        input_bytes = b'test location'
        loc_bytes = Location.from_bytes(input_bytes)
        self.assertEqual(bytes(loc_bytes), input_bytes)
        # comparison
        self.assertEqual(loc_bytes, input_bytes)
        self.assertNotEqual(loc_bytes, b'wrong bytes')
        # hash
        self.assertEqual(hash(loc_bytes), hash(input_bytes))

        # comparison between keywords
        self.assertEqual(loc_str, loc_bytes)
        self.assertNotEqual(loc_str, loc_int)

    def test_keyword(self) -> None:
        # from string
        input_string = 'test keyword'
        kw_str = Keyword.from_string(input_string)
        # conversion
        self.assertEqual(str(kw_str), input_string)
        # comparison
        self.assertEqual(kw_str, input_string)
        self.assertNotEqual(kw_str, 'wrong str')
        # hash
        self.assertEqual(hash(kw_str), hash(input_string))

        # from int
        input_int = 2**51 - 1
        kw_int = Keyword.from_int(input_int)
        self.assertEqual(int(kw_int), input_int)
        # comparison
        self.assertEqual(kw_int, input_int)
        self.assertNotEqual(kw_int, 2**51 - 2)
        # hash not working for int

        # from bytes
        input_bytes = b'test keyword'
        kw_bytes = Keyword.from_bytes(input_bytes)
        self.assertEqual(bytes(kw_bytes), input_bytes)
        # comparison
        self.assertEqual(kw_bytes, input_bytes)
        self.assertNotEqual(kw_bytes, b'wrong bytes')
        # hash
        self.assertEqual(hash(kw_bytes), hash(input_bytes))

        # comparison between keywords
        self.assertEqual(kw_str, kw_bytes)
        self.assertNotEqual(kw_str, kw_int)

    def test_label(self) -> None:
        rand_label = Label.random()
        self.assertIsInstance(rand_label, Label)

        saved_bytes = rand_label.to_bytes()
        reloaded_label = Label.from_bytes(saved_bytes)
        self.assertEqual(saved_bytes, reloaded_label.to_bytes())

    def test_masterkeys(self) -> None:
        msk = MasterKey.random()
        self.assertIsInstance(msk, MasterKey)

        saved_bytes = msk.to_bytes()
        reloaded_msk = MasterKey.from_bytes(saved_bytes)
        self.assertEqual(saved_bytes, reloaded_msk.to_bytes())

        with self.assertRaises(ValueError):
            MasterKey.from_bytes(b'wrong size')


class FindexHashmap:
    """Implement Findex callbacks using hashmaps"""

    def __init__(self, db: Dict[int, List[str]]):
        self.db = db
        self.entry_table: Dict[bytes, bytes] = {}
        self.chain_table: Dict[bytes, bytes] = {}

    # Create callback functions
    def fetch_entry(self, uids: List[bytes]) -> Sequence[Tuple[bytes, bytes]]:
        """DB request to fetch entry_table elements"""
        res = []
        for uid in uids:
            if uid in self.entry_table:
                res.append((uid, self.entry_table[uid]))
        return res

    def fetch_all_entry_table_uids(self) -> Set[bytes]:
        return set(self.entry_table.keys())

    def fetch_chain(self, uids: List[bytes]) -> Dict[bytes, bytes]:
        """DB request to fetch chain_table elements"""
        res = {}
        for uid in uids:
            if uid in self.chain_table:
                res[uid] = self.chain_table[uid]
        return res

    def upsert_entry(
        self, entries: Dict[bytes, Tuple[bytes, bytes]]
    ) -> Dict[bytes, bytes]:
        """DB request to upsert entry_table elements.
        WARNING: This implementation will not work with concurrency.
        """
        rejected_lines = {}
        for uid, (old_val, new_val) in entries.items():
            if uid in self.entry_table:
                if self.entry_table[uid] == old_val:
                    self.entry_table[uid] = new_val
                else:
                    rejected_lines[uid] = self.entry_table[uid]
            elif not old_val:
                self.entry_table[uid] = new_val
            else:
                raise Exception('Line got deleted in Entry Table')

        return rejected_lines

    def insert_entry(self, entries: Dict[bytes, bytes]) -> None:
        """DB request to insert entry_table elements"""
        for uid in entries:
            if uid in self.entry_table:
                raise KeyError('Conflict in Entry Table for UID: {uid}')
            self.entry_table[uid] = entries[uid]

    def insert_chain(self, entries: Dict[bytes, bytes]) -> None:
        """DB request to insert chain_table elements"""
        for uid in entries:
            if uid in self.chain_table:
                raise KeyError('Conflict in Chain Table for UID: {uid}')
            self.chain_table[uid] = entries[uid]

    def list_removed_locations(self, locations: List[Location]) -> List[Location]:
        res = []
        for loc in locations:
            if not int(loc) in self.db:
                res.append(loc)
        return res

    def update_lines(
        self,
        removed_chain_table_uids: List[bytes],
        new_encrypted_entry_table_items: Dict[bytes, bytes],
        new_encrypted_chain_table_items: Dict[bytes, bytes],
    ) -> None:
        # remove all entries from entry table
        self.entry_table.clear()

        # remove entries from chain table
        for uid in removed_chain_table_uids:
            del self.chain_table[uid]

        # insert new chains
        self.insert_chain(new_encrypted_chain_table_items)

        # insert newly encrypted entries
        self.insert_entry(new_encrypted_entry_table_items)


class TestFindex(unittest.TestCase):
    def setUp(self) -> None:
        # Create structures needed by Findex
        self.msk = MasterKey.random()
        self.label = Label.random()

        self.db = {
            1: ['Martin', 'Sheperd'],
            2: ['Martial', 'Wilkins'],
            3: ['John', 'Sheperd'],
        }

        self.findex_backend = FindexHashmap(self.db)
        self.findex_interface = InternalFindex()

    def test_upsert_search(self) -> None:
        indexed_values_and_keywords: IndexedValuesAndKeywords = {
            Location.from_int(k): v for k, v in self.db.items()
        }

        # Calling Upsert without setting the proper callbacks will raise an Exception
        with self.assertRaises(Exception):
            self.findex_interface.upsert_wrapper(
                self.msk, self.label, indexed_values_and_keywords, {}
            )

        # Set upsert callbacks here
        self.findex_interface.set_upsert_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.upsert_entry,
            self.findex_backend.insert_chain,
        )

        self.findex_interface.upsert_wrapper(
            self.msk, self.label, indexed_values_and_keywords, {}
        )
        self.assertEqual(len(self.findex_backend.entry_table), 5)
        self.assertEqual(len(self.findex_backend.chain_table), 5)

        # Set search callbacks here
        self.findex_interface.set_search_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.fetch_chain,
        )

        res = self.findex_interface.search_wrapper(
            self.msk, self.label, [Keyword.from_bytes(b'Martial')]
        )
        self.assertEqual(len(res), 1)
        self.assertEqual(len(res[Keyword.from_string('Martial')]), 1)
        self.assertEqual(int(res['Martial'][0]), 2)

        res = self.findex_interface.search_wrapper(
            self.msk, self.label, ['Sheperd', 'Wilkins']
        )
        self.assertEqual(len(res['Sheperd']), 2)
        self.assertEqual(len(res['Wilkins']), 1)

    def test_graph_upsert_search(self) -> None:
        self.findex_interface.set_upsert_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.upsert_entry,
            self.findex_backend.insert_chain,
        )
        self.findex_interface.set_search_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.fetch_chain,
        )

        indexed_values_and_keywords: IndexedValuesAndKeywords = {
            Location.from_int(k): v for k, v in self.db.items()
        }
        self.findex_interface.upsert_wrapper(
            self.msk, self.label, indexed_values_and_keywords, {}
        )

        # Adding custom keywords graph
        graph: IndexedValuesAndKeywords = {
            Keyword.from_string('Mart'): ['Mar'],
            Keyword.from_string('Marti'): ['Mart'],
            Keyword.from_string('Martin'): ['Marti'],
            Keyword.from_string('Martia'): ['Marti'],
            Keyword.from_string('Martial'): ['Martia'],
        }
        self.findex_interface.upsert_wrapper(self.msk, self.label, graph, {})

        self.assertEqual(len(self.findex_backend.entry_table), 9)
        self.assertEqual(len(self.findex_backend.chain_table), 9)

        res = self.findex_interface.search_wrapper(self.msk, self.label, ['Mar'])
        # 2 names starting with Mar
        self.assertEqual(len(res['Mar']), 2)

        # Test progress callback
        def false_progress_callback(res: ProgressResults) -> bool:
            self.assertEqual(len(res['Mar']), 1)
            return False

        res = self.findex_interface.search_wrapper(
            self.msk,
            self.label,
            ['Mar'],
            progress_callback=false_progress_callback,
        )
        # no locations returned since the progress_callback stopped the recursion
        self.assertEqual(len(res['Mar']), 0)

        def early_stop_progress_callback(res: ProgressResults) -> bool:
            if 'Martin' in res:
                return False
            return True

        res = self.findex_interface.search_wrapper(
            self.msk,
            self.label,
            ['Mar'],
            progress_callback=early_stop_progress_callback,
        )
        # only one location found after early stopping
        self.assertEqual(len(res['Mar']), 1)

    def test_compact(self) -> None:
        # use upsert, search and compact callbacks
        self.findex_interface.set_upsert_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.upsert_entry,
            self.findex_backend.insert_chain,
        )
        self.findex_interface.set_search_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.fetch_chain,
        )
        self.findex_interface.set_compact_callbacks(
            self.findex_backend.fetch_entry,
            self.findex_backend.fetch_chain,
            self.findex_backend.update_lines,
            self.findex_backend.list_removed_locations,
            self.findex_backend.fetch_all_entry_table_uids,
        )

        indexed_values_and_keywords: IndexedValuesAndKeywords = {
            Location.from_int(k): v for k, v in self.db.items()
        }
        self.findex_interface.upsert_wrapper(
            self.msk, self.label, indexed_values_and_keywords, {}
        )

        new_label = Label.random()
        res = self.findex_interface.search_wrapper(self.msk, new_label, ['Sheperd'])
        # new_label cannot search before compacting
        self.assertEqual(len(res['Sheperd']), 0)

        # removing 2nd db line
        del self.db[2]
        self.findex_interface.compact_wrapper(self.msk, self.msk, new_label, 1)

        # now new_label can perform search
        res = self.findex_interface.search_wrapper(self.msk, new_label, ['Sheperd'])
        self.assertEqual(len(res['Sheperd']), 2)
        # but not the previous label
        res = self.findex_interface.search_wrapper(self.msk, self.label, ['Sheperd'])
        self.assertEqual(len(res['Sheperd']), 0)

        # and the keywords corresponding to the 2nd line have been removed
        res = self.findex_interface.search_wrapper(
            self.msk, new_label, ['Martial', 'Wilkins']
        )
        assert len(res['Martial']) == 0
        assert len(res['Wilkins']) == 0


if __name__ == '__main__':
    unittest.main()
