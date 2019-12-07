import hashlib
import json
import rsa


class Voter:
    def __init__(self):
        (public_key, private_key) = rsa.newkeys(1024, poolsize=8)
        self.public_key = public_key
        self.private_key = private_key
        self.identity = "Иванов Иван Иванович"

    def decrypt_ballot(self, encrypted_ballot):
        """
        Расшифровывает закрытым ключом присланный бюллетень
        :param encrypted_ballot: зашифрованный бюллетень
        :return:
        """

        bytes_ballot = rsa.decrypt(encrypted_ballot, self.private_key)

        return json.loads(bytes_ballot.decode('utf-8'))

    @staticmethod
    def check_ballot_has_certain_fields(ballot):
        """
        Проверяет, что бюллетень строго состоит из 3 полей: y, хеш и подпись.
        Если есть другие поля, их убирает.
        :param ballot: бюллетень
        :return:
        """

        keys = ballot.keys()

        if len(keys) < 2:
            return False

        correct_keys = ['serial_number', 'digest']
        clear_ballot = {}

        for key in correct_keys:
            if key not in ballot:
                return False
            clear_ballot[key] = ballot[key]

        return clear_ballot

    @staticmethod
    def verify(ballot, signature, bd_public_key):
        """
        Проверяет цифровую подпись BD: вычисляет хеш и проверяет подпись.
        :param ballot: бюллетень
        :param signature: подпись бюллетеня BD
        :param bd_public_key: открытый ключ BD
        :return:
        """

        serial_number = ballot['serial_number']

        # берёт хеш от серийного номера
        bytes_serial_number = str(serial_number).encode()
        digest = hashlib.md5(bytes_serial_number).hexdigest()

        if ballot['digest'] != digest:
            return False

        # TODO: извлекать подпись из бюллетеня
        try:
            rsa.verify((str(serial_number) + digest).encode(), signature, bd_public_key)
        except rsa.pkcs1.VerificationError:
            return False

        return True

    def check_ballot(self, ballot, signature, bd_public_key):
        """
        Проверяет, что бюллетень не подделали.
        :param ballot: бюллетень
        :param signature: подпись бюллетеня BD
        :param bd_public_key: открытый ключ BD
        :return:
        """

        # TODO: не передавать подпись отдельно
        return self.check_ballot_has_certain_fields(ballot) and self.verify(ballot, signature, bd_public_key)
