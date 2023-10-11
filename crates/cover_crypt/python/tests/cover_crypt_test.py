# -*- coding: utf-8 -*-
import unittest

from cloudproof_cover_crypt import (
    Attribute,
    CoverCrypt,
    MasterPublicKey,
    MasterSecretKey,
    Policy,
    PolicyAxis,
    SymmetricKey,
    UserSecretKey,
)


class TestPolicy(unittest.TestCase):
    def policy(self) -> Policy:
        policy = Policy()
        policy.add_axis(
            PolicyAxis(
                'Country',
                [
                    ('France', False),
                    ('UK', False),
                    ('Spain', False),
                    ('Germany', False),
                ],
                False,
            )
        )
        policy.add_axis(
            PolicyAxis(
                'Secrecy', [('Low', False), ('Medium', False), ('High', True)], True
            )
        )
        return policy

    def test_attribute(self) -> None:
        attr = Attribute('Country', 'France')
        self.assertEqual(attr.to_string(), 'Country::France')

        new_attr = Attribute.from_string('Country::Japan')
        self.assertIsInstance(new_attr, Attribute)
        self.assertEqual(new_attr.get_axis(), 'Country')
        self.assertEqual(new_attr.get_name(), 'Japan')

    def test_policy_axis(self) -> None:
        country_axis = PolicyAxis(
            'Country',
            [('France', False), ('UK', False), 'Spain', 'Germany'],
            False,
        )
        self.assertEqual(
            country_axis.to_string(),
            'Country: [AttributeBuilder { name: "France", encryption_hint: Classic }, AttributeBuilder { name: "UK", encryption_hint: Classic }, AttributeBuilder { name: "Spain", encryption_hint: Classic }, AttributeBuilder { name: "Germany", encryption_hint: Classic }], hierarchical: false',
        )
        secrecy_axis = PolicyAxis(
            'Secrecy',
            [('Low', False), 'Medium', ('High', True)],
            True,
        )
        self.assertEqual(
            secrecy_axis.to_string(),
            'Secrecy: [AttributeBuilder { name: "Low", encryption_hint: Classic }, AttributeBuilder { name: "Medium", encryption_hint: Classic }, AttributeBuilder { name: "High", encryption_hint: Hybridized }], hierarchical: true',
        )

        self.assertTrue(PolicyAxis('Test', [], False).is_empty())
        self.assertEqual(country_axis.len(), 4)
        self.assertEqual(len(country_axis.get_attributes()), 4)
        self.assertFalse(country_axis.is_hierarchical())
        self.assertTrue(secrecy_axis.is_hierarchical())
        self.assertEqual(secrecy_axis.get_name(), 'Secrecy')

    def test_policy_creation_rotation(self) -> None:
        policy = self.policy()
        # test attributes
        attributes = policy.attributes()
        self.assertEqual(len(attributes), 4 + 3)
        # rotate
        france_attribute = Attribute('Country', 'France')
        france_value = policy.attribute_current_value(france_attribute)
        self.assertEqual(france_value, 1)
        policy.rotate(france_attribute)
        new_france_value = policy.attribute_current_value(france_attribute)
        self.assertEqual(new_france_value, 8)
        self.assertEqual(policy.attribute_values(france_attribute), [8, 1])
        # clear rotation
        policy.clear_old_rotations(france_attribute)
        self.assertEqual(policy.attribute_values(france_attribute), [8])
        # clearing rotation of non existing attribute will raise an Error
        with self.assertRaises(Exception):
            policy.clear_old_rotations(Attribute('Department', 'Missing'))

    def test_edit_policy(self) -> None:
        # Create and initialize policy
        policy = self.policy()
        self.assertEqual(len(policy.attributes()), 7)

        # Rename R&D to Research
        policy.rename_attribute(Attribute('Country', 'Spain'), 'Espagne')

        # Try renaming Research to already used name MKG
        with self.assertRaises(Exception):
            policy.rename_attribute(Attribute('Country', 'Japan'), 'Japon')
        self.assertEqual(len(policy.attributes()), 7)

        # Add new attribute Japan
        new_attr = Attribute('Country', 'Japan')
        policy.add_attribute(new_attr, False)
        self.assertEqual(len(policy.attributes()), 8)

        # Try adding already existing attribute
        duplicate_attr = Attribute('Country', 'France')
        with self.assertRaises(Exception):
            policy.add_attribute(duplicate_attr, False)

        # Try adding attribute to non-existing dimension
        missing_dimension = Attribute('Missing', 'dimension')
        with self.assertRaises(Exception):
            policy.add_attribute(missing_dimension, False)

        # Remove research attribute
        delete_attr = Attribute('Country', 'Espagne')
        policy.remove_attribute(delete_attr)
        self.assertEqual(len(policy.attributes()), 7)

        # Duplicate remove
        with self.assertRaises(Exception):
            policy.remove_attribute(delete_attr)

        # Missing dimension remove
        with self.assertRaises(Exception):
            policy.remove_attribute(missing_dimension)

        # Remove all attributes from a dimension
        policy.remove_attribute(new_attr)
        policy.remove_attribute(Attribute('Country', 'France'))
        policy.remove_attribute(Attribute('Country', 'UK'))
        policy.remove_attribute(Attribute('Country', 'Germany'))
        self.assertEqual(len(policy.attributes()), 3)

        # Add new dimension
        new_dimension = PolicyAxis(
            'DimensionTest',
            [
                ('Attr1', False),
                ('Attr2', False),
            ],
            False,
        )
        policy.add_axis(new_dimension)
        self.assertEqual(len(policy.attributes()), 5)

        # Remove the new dimension
        policy.remove_axis('DimensionTest')
        self.assertEqual(len(policy.attributes()), 3)

        # Try removing non-existing dimension
        with self.assertRaises(Exception):
            policy.remove_axis('MissingDim')

        # Try modifying hierarchical dimension
        with self.assertRaises(Exception):
            policy.remove_attribute(Attribute('Secrecy', 'Top Secret'))

        # Removing a hierarchical dimension is permitted
        policy.remove_axis('Secrecy')
        self.assertEqual(len(policy.attributes()), 0)

    def test_policy_cloning_serialization(self) -> None:
        policy = self.policy()

        copy_policy = policy.deep_copy()
        self.assertIsInstance(copy_policy, Policy)

        json_str = policy.to_bytes()
        self.assertEqual(json_str, copy_policy.to_bytes())

        deserialized_policy = Policy.from_bytes(json_str)
        self.assertIsInstance(deserialized_policy, Policy)

        with self.assertRaises(Exception):
            Policy.from_bytes('wrong data format'.encode())


class TestKeyGeneration(unittest.TestCase):
    def setUp(self) -> None:
        country_axis = PolicyAxis(
            'Country',
            [('France', False), ('UK', False), ('Spain', False), ('Germany', False)],
            False,
        )
        secrecy_axis = PolicyAxis(
            'Secrecy', [('Low', False), ('Medium', False), ('High', True)], True
        )
        self.policy = Policy()
        self.policy.add_axis(country_axis)
        self.policy.add_axis(secrecy_axis)

        self.cc = CoverCrypt()
        self.msk, self.pk = self.cc.generate_master_keys(self.policy)

    def test_master_key_serialization(self) -> None:
        # test serialization
        msk_bytes = self.msk.to_bytes()
        self.assertIsInstance(MasterSecretKey.from_bytes(msk_bytes), MasterSecretKey)
        with self.assertRaises(Exception):
            MasterSecretKey.from_bytes(b'wrong data')

        pk_bytes = self.pk.to_bytes()
        self.assertIsInstance(MasterPublicKey.from_bytes(pk_bytes), MasterPublicKey)
        with self.assertRaises(Exception):
            MasterPublicKey.from_bytes(b'wrong data')

    def test_user_key_serialization(self) -> None:
        usk = self.cc.generate_user_secret_key(
            self.msk,
            'Secrecy::High && (Country::France || Country::Spain)',
            self.policy,
        )

        # test serialization
        usk_bytes = usk.to_bytes()
        deserialized_usk = UserSecretKey.from_bytes(usk_bytes)
        self.assertIsInstance(deserialized_usk, UserSecretKey)

        # test KMAC authenticity of the deserialized key
        france_attribute = Attribute('Country', 'France')
        self.policy.rotate(france_attribute)
        self.cc.update_master_keys(self.policy, self.msk, self.pk)
        self.cc.refresh_user_secret_key(
            deserialized_usk,
            'Secrecy::High && (Country::France || Country::Spain)',
            self.msk,
            self.policy,
            keep_old_accesses=True,
        )

        with self.assertRaises(Exception):
            UserSecretKey.from_bytes(b'wrong data')

    def test_sym_key_serialization(self) -> None:
        sym_key, _ = self.cc.encrypt_header(
            self.policy,
            'Secrecy::High && Country::Germany',
            self.pk,
            None,
            None,
        )
        sym_key_bytes = sym_key.to_bytes()
        self.assertIsInstance(SymmetricKey.from_bytes(sym_key_bytes), SymmetricKey)

        with self.assertRaises(Exception):
            SymmetricKey.from_bytes(b'wrong data')


class TestEncryption(unittest.TestCase):
    def setUp(self) -> None:
        country_axis = PolicyAxis(
            'Country',
            [('France', False), ('UK', False), ('Spain', False), ('Germany', False)],
            False,
        )
        secrecy_axis = PolicyAxis(
            'Secrecy', [('Low', False), ('Medium', False), ('High', True)], True
        )
        self.policy = Policy()
        self.policy.add_axis(country_axis)
        self.policy.add_axis(secrecy_axis)

        self.cc = CoverCrypt()
        self.msk, self.pk = self.cc.generate_master_keys(self.policy)

        self.plaintext = b'My secret data'
        self.header_metadata = bytes([0, 0, 0, 0, 0, 0, 0, 1])
        self.authenticated_data = b'auth'

    def test_simple_encryption_decryption_without_metadata(self) -> None:
        ciphertext = self.cc.encrypt(
            self.policy, 'Secrecy::Medium && Country::Germany', self.pk, self.plaintext
        )

        sec_high_ger_user = self.cc.generate_user_secret_key(
            self.msk,
            'Secrecy::High && Country::Germany',
            self.policy,
        )

        # Successful decryption
        plaintext, _ = self.cc.decrypt(sec_high_ger_user, ciphertext)
        self.assertEqual(plaintext, self.plaintext)

    def test_simple_encryption_decryption_with_metadata(self) -> None:
        ciphertext = self.cc.encrypt(
            self.policy,
            'Secrecy::High && Country::France',
            self.pk,
            self.plaintext,
            self.header_metadata,
            self.authenticated_data,
        )

        sec_high_fr_sp_user = self.cc.generate_user_secret_key(
            self.msk,
            'Secrecy::High && (Country::France || Country::Spain)',
            self.policy,
        )

        # Successful decryption
        plaintext, header_metadata = self.cc.decrypt(
            sec_high_fr_sp_user, ciphertext, self.authenticated_data
        )
        self.assertEqual(plaintext, self.plaintext)
        self.assertEqual(header_metadata, bytes(self.header_metadata))

        # Wrong key
        sec_low_fr_sp_user = self.cc.generate_user_secret_key(
            self.msk, 'Secrecy::Low && (Country::France || Country::Spain)', self.policy
        )

        with self.assertRaises(Exception):
            self.cc.decrypt(sec_low_fr_sp_user, ciphertext, self.authenticated_data)

    def test_policy_rotation_encryption_decryption(self) -> None:
        ciphertext = self.cc.encrypt(
            self.policy,
            'Secrecy::High && Country::France',
            self.pk,
            self.plaintext,
            self.header_metadata,
            self.authenticated_data,
        )

        sec_high_fr_sp_user = self.cc.generate_user_secret_key(
            self.msk,
            'Secrecy::High && (Country::France || Country::Spain)',
            self.policy,
        )

        france_attribute = Attribute('Country', 'France')
        self.policy.rotate(france_attribute)

        self.cc.update_master_keys(self.policy, self.msk, self.pk)
        new_plaintext = b'My secret data 2'
        new_ciphertext = self.cc.encrypt(
            self.policy,
            'Secrecy::High && Country::France',
            self.pk,
            new_plaintext,
            self.header_metadata,
            self.authenticated_data,
        )

        # user cannot decrypt the new message until its key is refreshed
        with self.assertRaises(Exception):
            self.cc.decrypt(
                sec_high_fr_sp_user, new_ciphertext, self.authenticated_data
            )

        # new user can still decrypt old message with keep_old_accesses
        self.cc.refresh_user_secret_key(
            sec_high_fr_sp_user,
            'Secrecy::High && (Country::France || Country::Spain)',
            self.msk,
            self.policy,
            keep_old_accesses=True,
        )

        plaintext, _ = self.cc.decrypt(
            sec_high_fr_sp_user, ciphertext, self.authenticated_data
        )
        self.assertEqual(plaintext, self.plaintext)

        # new user key can no longer decrypt the old message
        self.cc.refresh_user_secret_key(
            sec_high_fr_sp_user,
            'Secrecy::High && (Country::France || Country::Spain)',
            self.msk,
            self.policy,
            keep_old_accesses=False,
        )
        with self.assertRaises(Exception):
            self.cc.decrypt(sec_high_fr_sp_user, ciphertext, self.authenticated_data)

        plaintext, _ = self.cc.decrypt(
            sec_high_fr_sp_user, new_ciphertext, self.authenticated_data
        )
        self.assertEqual(bytes(plaintext), new_plaintext)

    def test_decomposed_encryption_decryption(self) -> None:
        """Test individually the header and the symmetric encryption/decryption"""
        sym_key, enc_header = self.cc.encrypt_header(
            self.policy,
            'Secrecy::Medium && Country::UK',
            self.pk,
            self.header_metadata,
            self.authenticated_data,
        )

        ciphertext = self.cc.encrypt_symmetric_block(
            sym_key, self.plaintext, self.authenticated_data
        )

        sec_med_uk_user = self.cc.generate_user_secret_key(
            self.msk, 'Secrecy::Medium && Country::UK', self.policy
        )

        decrypted_sym_key, decrypted_metadata = self.cc.decrypt_header(
            sec_med_uk_user, enc_header, self.authenticated_data
        )
        self.assertEqual(decrypted_metadata, bytes(self.header_metadata))

        decrypted_data = self.cc.decrypt_symmetric_block(
            decrypted_sym_key, ciphertext, self.authenticated_data
        )
        self.assertEqual(bytes(decrypted_data), self.plaintext)

    def test_add_attribute(self) -> None:
        # User secret key
        decryption_policy = 'Secrecy::Low'
        low_secret_usk = self.cc.generate_user_secret_key(
            self.msk, decryption_policy, self.policy
        )

        # Add sales department
        self.policy.add_attribute(Attribute('Country', 'Japan'), False)

        # Update the master keys
        self.cc.update_master_keys(self.policy, self.msk, self.pk)

        # Encrypt
        plaintext = b'My secret data'
        ciphertext = self.cc.encrypt(
            self.policy,
            'Secrecy::Low && Country::Japan',
            self.pk,
            plaintext,
        )

        # User cannot decrypt new message without refreshing its key
        with self.assertRaises(Exception):
            self.cc.decrypt(low_secret_usk, ciphertext)

        self.cc.refresh_user_secret_key(
            low_secret_usk, decryption_policy, self.msk, self.policy, False
        )

        decrypted_text, _ = self.cc.decrypt(low_secret_usk, ciphertext)
        self.assertEqual(decrypted_text, plaintext)

    def test_delete_attribute(self) -> None:
        # User secret key
        decryption_policy = 'Secrecy::High && (Country::France || Country::UK)'
        usk = self.cc.generate_user_secret_key(self.msk, decryption_policy, self.policy)

        # Encrypt
        plaintext = b'My secret data'
        ciphertext = self.cc.encrypt(
            self.policy,
            'Secrecy::High && Country::France',
            self.pk,
            plaintext,
        )

        # Remove the attribute
        self.policy.remove_attribute(Attribute('Country', 'France'))

        # Update the master keys
        self.cc.update_master_keys(self.policy, self.msk, self.pk)

        # Decrypt with old key
        decrypted_text, _ = self.cc.decrypt(usk, ciphertext)
        self.assertEqual(decrypted_text, plaintext)

        # Refreshing the user key will remove access to removed partitions
        new_decryption_policy = 'Secrecy::High && Country::UK'
        self.cc.refresh_user_secret_key(
            usk, new_decryption_policy, self.msk, self.policy, True
        )
        with self.assertRaises(Exception):
            self.cc.decrypt(usk, ciphertext)

    def test_disable_attribute(self) -> None:
        # User secret key
        decryption_policy = 'Secrecy::High && Country::France'
        usk = self.cc.generate_user_secret_key(self.msk, decryption_policy, self.policy)

        # Encrypt
        plaintext = b'My secret data'
        ciphertext = self.cc.encrypt(
            self.policy,
            'Secrecy::High && Country::France',
            self.pk,
            plaintext,
        )

        # Disable the attribute
        self.policy.disable_attribute(Attribute('Country', 'France'))

        # Update the master keys
        self.cc.update_master_keys(self.policy, self.msk, self.pk)

        # Can no longer encrypt for this attribute
        with self.assertRaises(Exception):
            self.cc.encrypt(
                self.policy,
                'Secrecy::High && Country::France',
                self.pk,
                b'Test',
            )

        # Refreshing the user key will keep access to the attribute
        new_decryption_policy = 'Secrecy::High && Country::France'
        self.cc.refresh_user_secret_key(
            usk, new_decryption_policy, self.msk, self.policy, False
        )
        decrypted_text, _ = self.cc.decrypt(usk, ciphertext)
        self.assertEqual(decrypted_text, plaintext)

    def test_rename_attribute(self) -> None:
        # User secret key
        decryption_policy = 'Secrecy::High && Country::Spain'
        usk = self.cc.generate_user_secret_key(self.msk, decryption_policy, self.policy)

        # Encrypt
        plaintext = b'My secret data'
        ciphertext = self.cc.encrypt(
            self.policy,
            'Secrecy::High && Country::Spain',
            self.pk,
            plaintext,
        )

        # Disable the attribute
        self.policy.rename_attribute(Attribute('Country', 'Spain'), 'Espagne')

        # Update the master keys
        self.cc.update_master_keys(self.policy, self.msk, self.pk)

        # Refreshing the user key will keep access to the attribute
        new_decryption_policy = 'Secrecy::High && Country::Espagne'
        self.cc.refresh_user_secret_key(
            usk, new_decryption_policy, self.msk, self.policy, False
        )
        decrypted_text, _ = self.cc.decrypt(usk, ciphertext)
        self.assertEqual(decrypted_text, plaintext)


if __name__ == '__main__':
    unittest.main()
