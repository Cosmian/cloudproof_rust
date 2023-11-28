# -*- coding: utf-8 -*-
import os
import requests
import redis
import unittest

from typing import Dict, List, Sequence, Set, Tuple

from cloudproof_findex import (
    AuthorizationToken,
    Findex,
    IndexedValuesAndKeywords,
    Keyword,
    Label,
    Location,
    Key,
    ProgressResults,
    PythonCallbacks,
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
        loi32 = Location.from_int(input_int)
        self.assertEqual(int(loi32), input_int)
        # comparison
        self.assertEqual(loi32, input_int)
        self.assertNotEqual(loi32, 2**51 - 2)
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
        self.assertNotEqual(loc_str, loi32)

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

    def test_keys(self) -> None:
        msk = Key.random()
        self.assertIsInstance(msk, Key)

        saved_bytes = msk.to_bytes()
        reloaded_msk = Key.from_bytes(saved_bytes)
        self.assertEqual(saved_bytes, reloaded_msk.to_bytes())

        with self.assertRaises(ValueError):
            Key.from_bytes(b'wrong size')


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


# Define closures to implement an in-memory backend.
def define_custom_backends(is_with_test: bool = False):
    entry_table: dict = {}
    chain_table: dict = {}

    def fetch(uids, table: dict):
        res = {}
        for uid in uids:
            if uid in table:
                res[uid] = table.get(uid)
        return res

    def upsert_entries(old_values: dict, new_values: dict):
        res = {}
        for uid, new_value in new_values.items():
            if old_values.get(uid) == entry_table.get(uid):
                entry_table[uid] = new_value
            elif uid in entry_table:
                res[uid] = entry_table[uid]
        return res

    def insert_links(new_links: Dict):
        for uid, value in new_links.items():
            if uid in chain_table:
                raise ValueError('collision in the Chain Table on uid: ' + uid)
            chain_table[uid] = value

    def delete(uids, table: Dict):
        for uid in uids:
            table.pop(uid)

    def dump_entry_tokens():
        return entry_table.keys()

    if is_with_test:
        k1 = 'my first key'
        k2 = 'my second key'
        v1 = [1, 2, 3]
        v2 = [4, 5, 6]
        v3 = [7, 8, 9]

        # Test values can be upserted.
        res = upsert_entries({}, {k1: v1})
        assert not res
        assert v1 == fetch([k1], entry_table)[k1]

        res = upsert_entries({k1: v1}, {k1: v2})
        assert not res
        assert v2 == fetch([k1], entry_table)[k1]

        res = upsert_entries({k1: v1}, {k1: v3})
        assert res == {k1: v2}
        assert v2 == fetch([k1], entry_table)[k1]

        assert {k1} == dump_entry_tokens()

        insert_links({k1: v1})
        assert v1 == fetch([k1], chain_table)[k1]
        assert not fetch([k2], chain_table)

        try:
            insert_links({k1: v2})
            raise ValueError('collision on key: ' + k1)
        except:
            pass

        # clear test values
        entry_table = {}
        chain_table = {}

    entry_callbacks = PythonCallbacks.new()
    entry_callbacks.set_fetch(lambda uids: fetch(uids, entry_table))
    entry_callbacks.set_upsert(upsert_entries)
    entry_callbacks.set_delete(lambda uids: delete(uids, entry_table))
    entry_callbacks.set_dump_tokens(dump_entry_tokens)

    chain_callbacks = PythonCallbacks.new()
    chain_callbacks.set_fetch(lambda uids: fetch(uids, chain_table))
    chain_callbacks.set_insert(insert_links)
    chain_callbacks.set_delete(lambda uids: delete(uids, chain_table))

    return (entry_callbacks, chain_callbacks)


class TestFindex(unittest.TestCase):
    def setUp(self) -> None:
        # Create structures needed by Findex
        self.findex_key = Key.random()
        self.label = Label.random()

        self.db = {
            1: ['Martin', 'Sheperd'],
            2: ['Martial', 'Wilkins'],
            3: ['John', 'Sheperd'],
        }

        # Parameters used by the cloud backend.
        url = 'http://localhost:8080'
        res = requests.post(
            url + '/indexes',
            headers={'Content-Type': 'application/json'},
            json={'name': 'Test'},
            timeout=5,
        )
        response = res.json()
        token = AuthorizationToken.new(
            index_id=response['public_id'],
            findex_key=Key.random(),
            fetch_entries_key=Key.from_bytes(response['fetch_entries_key']),
            fetch_chains_key=Key.from_bytes(response['fetch_chains_key']),
            upsert_entries_key=Key.from_bytes(response['upsert_entries_key']),
            insert_chains_key=Key.from_bytes(response['insert_chains_key']),
        )

        # Parameters used by the custom backend.
        (entry_callbacks, chain_callbacks) = define_custom_backends()

        sqlite_db = '/tmp/cloudproof_findex.sqlite'
        redis_host = 'localhost'
        redis_port = 6379
        redis_url = f'redis://{redis_host}:{redis_port}'

        if os.path.exists(sqlite_db):
            os.remove(sqlite_db)

        r = redis.Redis(host=redis_host, port=redis_port, db=0)
        print(redis_url)
        r.flushdb()

        self.findex_interfaces = {
            'sqlite': Findex.new_with_sqlite_backend(
                self.findex_key,
                self.label,
                sqlite_db,
                sqlite_db,
            ),
            'redis': Findex.new_with_redis_backend(
                self.findex_key,
                self.label,
                redis_url,
                redis_url,
            ),
            'rest': Findex.new_with_rest_backend(
                self.findex_key, self.label, str(token), url
            ),
            'custom': Findex.new_with_custom_backend(
                self.findex_key, self.label, entry_callbacks, chain_callbacks
            ),
        }

    def test_upsert(self) -> None:
        indexed_values_and_keywords: IndexedValuesAndKeywords = {
            Location.from_int(k): v for k, v in self.db.items()
        }

        for backend, instance in self.findex_interfaces.items():
            print('Test upserting on {} backend.', backend)
            res = instance.add(indexed_values_and_keywords)
            # 5 keywords returned since "Sheperd" is duplicated
            self.assertEqual(len(res), 5)

            res = instance.add({Location.from_int(4): ['John', 'Snow']})
            # 1 keyword returned since "John" is already indexed
            self.assertEqual(res, set(['Snow']))

    def test_upsert_search(self) -> None:
        indexed_values_and_keywords: IndexedValuesAndKeywords = {
            Location.from_int(k): v for k, v in self.db.items()
        }

        for backend, instance in self.findex_interfaces.items():
            print('Test upserting and search on {} backend.', backend)
            instance.add(indexed_values_and_keywords)

            res = instance.search([Keyword.from_bytes(b'Martial')])
            self.assertEqual(len(res), 1)
            self.assertEqual(len(res[Keyword.from_string('Martial')]), 1)
            self.assertEqual(int(res['Martial'][0]), 2)

            res = instance.search(['Sheperd', 'Wilkins'])
            self.assertEqual(len(res['Sheperd']), 2)
            self.assertEqual(len(res['Wilkins']), 1)

    def test_graph_upsert_search(self) -> None:
        indexed_values_and_keywords: IndexedValuesAndKeywords = {
            Location.from_int(k): v for k, v in self.db.items()
        }

        for backend, instance in self.findex_interfaces.items():
            print(f'Test graph upserting and search on {backend} backend.')
            instance.add(indexed_values_and_keywords)

            # Adding custom keywords graph
            graph: IndexedValuesAndKeywords = {
                Keyword.from_string('Mart'): ['Mar'],
                Keyword.from_string('Marti'): ['Mart'],
                Keyword.from_string('Martin'): ['Marti'],
                Keyword.from_string('Martia'): ['Marti'],
                Keyword.from_string('Martial'): ['Martia'],
            }
            instance.add(graph)

            res = instance.search(['Mar'])
            # 2 names starting with Mar
            self.assertEqual(len(res['Mar']), 2)

            # Test progress callback
            def false_progress_callback(res: ProgressResults) -> bool:
                self.assertEqual(len(res['Mar']), 1)
                return True

            res = instance.search(
                ['Mar'],
                interrupt=false_progress_callback,
            )
            # no locations returned since the progress_callback stopped the recursion
            self.assertEqual(len(res['Mar']), 0)

            def early_stop_progress_callback(res: ProgressResults) -> bool:
                if 'Martin' in res:
                    return True
                return False

            res = instance.search(
                ['Mar'],
                interrupt=early_stop_progress_callback,
            )
            # only one location found after early stopping
            self.assertEqual(len(res['Mar']), 1)

    def test_compact(self) -> None:
        indexed_values_and_keywords: IndexedValuesAndKeywords = {
            Location.from_int(k): v for k, v in self.db.items()
        }
        del self.db[2]

        interfaces = [
            (backend, instance)
            for backend, instance in self.findex_interfaces.items()
            if backend == 'sqlite'
        ]

        for backend, instance in interfaces:
            print(f'Test compacting and search on {backend} backend.')

            instance.add(indexed_values_and_keywords)

            # removing 2nd db line
            new_label = Label.random()

            def filter_obsolete_data(dataset: Set[Location]):
                res = set()
                for data in dataset:
                    if int(data) in self.db:
                        res.add(data)
                return res

            instance.compact(self.findex_key, new_label, 1, filter_obsolete_data)

            # now new_label can perform search
            res = instance.search(['Sheperd'])
            self.assertEqual(len(res['Sheperd']), 2)

            # and the keywords corresponding to the 2nd line have been removed
            res = instance.search(['Martial', 'Wilkins'])
            self.assertEqual(len(res['Martial']), 0)
            self.assertEqual(len(res['Wilkins']), 0)


if __name__ == '__main__':
    define_custom_backends(True)
    unittest.main()
