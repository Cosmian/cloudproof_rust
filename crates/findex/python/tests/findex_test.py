# -*- coding: utf-8 -*-
import os
import requests
import redis
import unittest

from typing import Set

from cloudproof_findex import (
    AuthorizationToken,
    Findex,
    IndexedValuesAndKeywords,
    Keyword,
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

    def test_keys(self) -> None:
        msk = Key.random()
        self.assertIsInstance(msk, Key)

        saved_bytes = msk.to_bytes()
        reloaded_msk = Key.from_bytes(saved_bytes)
        self.assertEqual(saved_bytes, reloaded_msk.to_bytes())

        with self.assertRaises(ValueError):
            Key.from_bytes(b'wrong size')


def define_custom_db_interface(is_with_test: bool = False):
    table: dict = {}

    def fetch(uids):
        res = {}
        for uid in uids:
            if uid in table:
                res[uid] = table[uid]
        return res

    def upsert(old_values: dict, new_values: dict):
        res = {}
        for uid, new_value in new_values.items():
            current_value = table.get(uid)
            old_value = old_values.get(uid)
            if old_value == current_value:
                table[uid] = new_value
            elif not current_value:
                raise ValueError('The current value needs to be defined as long as the old value is defined ')
            else:
                res[uid] = current_value
        return res

    def insert(items):
        for uid, value in items.items():
            if uid in table:
                raise ValueError('collision in insert operation on UID: ' + uid)
            table[uid] = value

    def delete(uids):
        for uid in uids:
            table.pop(uid)

    def dump_tokens():
        return table.keys()

    if is_with_test:
        k1 = 'my first key'
        k2 = 'my second key'
        k3 = 'my third key'
        v1 = [1, 2, 3]
        v2 = [4, 5, 6]
        v3 = [7, 8, 9]

        # Test values can be upserted.
        res = upsert({}, {k1: v1})
        assert not res
        assert v1 == fetch([k1])[k1]

        res = upsert({k1: v1}, {k1: v2})
        assert not res
        assert v2 == fetch([k1])[k1]

        res = upsert({k1: v1}, {k1: v3})
        assert res == {k1: v2}
        assert v2 == fetch([k1])[k1]

        assert {k1} == dump_tokens()

        insert({k3: v1})
        assert v1 == fetch([k3])[k3]
        assert not fetch([k2])

        try:
            insert({k1: v2})
            raise ValueError('collision on key: ' + k1)
        except:
            pass

        # clear test values
        table = {}

    in_memory_db_interface = PythonCallbacks.new()
    in_memory_db_interface.set_fetch(fetch)
    in_memory_db_interface.set_upsert(upsert)
    in_memory_db_interface.set_insert(insert)
    in_memory_db_interface.set_delete(delete)
    in_memory_db_interface.set_dump_tokens(dump_tokens)

    return in_memory_db_interface


class TestFindex(unittest.TestCase):
    def setUp(self) -> None:
        # Create structures needed by Findex
        self.findex_key = Key.random()
        self.label = "My label."

        self.db = {
            1: ['Martin', 'Sheperd'],
            2: ['Martial', 'Wilkins'],
            3: ['John', 'Sheperd'],
        }

        # Parameters used by the REST interface
        rest_server_url = 'http://localhost:8080'
        res = requests.post(
            rest_server_url + '/indexes',
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

        in_memory_db_interface = define_custom_db_interface()

        sqlite_path = '/tmp/cloudproof_findex.sqlite'
        redis_host = 'localhost'
        redis_port = 6379
        redis_url = f'redis://{redis_host}:{redis_port}'

        if os.path.exists(sqlite_path):
            os.remove(sqlite_path)

        r = redis.Redis(host=redis_host, port=redis_port, db=0)
        print(redis_url)
        r.flushdb()

        self.findex_interfaces = {
            'sqlite': Findex.new_with_sqlite_interface(
                self.findex_key,
                self.label,
                sqlite_path,
            ),
            'redis': Findex.new_with_redis_interface(
                self.findex_key,
                self.label,
                redis_url,
            ),
            'rest': Findex.new_with_rest_interface(self.label,
                                                   str(token),
                                                   rest_server_url),
            'custom': Findex.new_with_custom_interface(
                self.findex_key, self.label, in_memory_db_interface, in_memory_db_interface
            ),
        }

    def test_upsert(self) -> None:
        indexed_values_and_keywords: IndexedValuesAndKeywords = {
            Location.from_int(k): v for k, v in self.db.items()
        }

        for interface, instance in self.findex_interfaces.items():
            print('Test upserting on {} interface.', interface)
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

        for interface, instance in self.findex_interfaces.items():
            print('Test upserting and search on {} interface.', interface)
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

        for interface, instance in self.findex_interfaces.items():
            print(f'Test graph upserting and search on {interface} interface.')
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

        interfaces = [
            (interface, instance)
            for interface, instance in self.findex_interfaces.items()
            if interface == 'sqlite'
        ]

        for interface, instance in interfaces:
            print(f'Test compacting and search on {interface} interface.')

            instance.add(indexed_values_and_keywords)

            # removing 2nd db line
            new_label = "My renewed label"

            filtered_locations = { Location.from_int(2) }

            def filter_obsolete_data(dataset: Set[Location]):
                res = set()
                for data in dataset:
                    if data not in filtered_locations:
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
    define_custom_db_interface(True)
    unittest.main()
