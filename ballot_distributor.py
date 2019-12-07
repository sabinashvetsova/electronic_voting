import json
import rsa.randnum
import hashlib


class BallotDistributor:
    def __init__(self):
        (public_key, private_key) = rsa.newkeys(1024, poolsize=8)
        self.public_key = public_key
        self.private_key = private_key

    @staticmethod
    def generate_serial_number():
        """
        Генерирует уникальный серийный номер y для избирателя
        :return:
        """

        # TODO: добавить уникальность
        serial_number = rsa.randnum.read_random_int(32)
        return serial_number

    @staticmethod
    def save_serial_number_and_voter_identity(serial_number, identity):
        """
        Сохраняет в БД серийный номер и идентификатор избирателя.
        :param serial_number: серийный номер y
        :param identity: личность избирателя
        :return:
        """

        # TODO: добавить работу с БД

    def get_ballot(self, serial_number):
        """
        Возвращает пустой бюллетень в виде словаря в json-формате с 3 ключами:
        serial_number - серийный номер y,
        digest - хеш от y,
        signature - подпись BD на первые 2 поля
        :param serial_number: серийный номер y
        :return:
        """

        # берёт хеш от серийного номера
        bytes_string = str(serial_number).encode()
        digest = hashlib.md5(bytes_string).hexdigest()

        # подписывает серийный номер и хеш
        signature = rsa.sign((str(serial_number) + digest).encode(), self.private_key, 'MD5')

        return {
            "serial_number": serial_number,
            "digest": digest,
            "signature": signature,
        }

    @staticmethod
    def encrypt_ballot(ballot, voter_public_key):
        """
        Зашифровывает бюллетень открытым ключом избирателя
        :param ballot: бюллетень
        :param voter_public_key: открытый ключ избирателя
        :return:
        """

        # TODO: сделать возможным шифрование подписи, пока ошибка
        # TypeError: Object of type bytes is not JSON serializable
        del ballot["signature"]

        bytes_ballot = json.dumps(ballot).encode('utf-8')

        return rsa.encrypt(bytes_ballot, voter_public_key)
