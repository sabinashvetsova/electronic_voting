import rsa


class CertifyingAuthority:
    def __init__(self):
        (public_key, private_key) = rsa.newkeys(1024, poolsize=8)
        self.public_key = public_key
        self.private_key = private_key

    def issue_certificate(self, voter_identity, voter_public_key):
        """
        Выдаёт сертификат в виде словаря в json-формате с 3 ключами:
        identity - личность избирателя,
        public_key - открытый ключ избирателя,
        signature - подпись CA на первые 2 поля
        :param voter_identity: личность избирателя
        :param voter_public_key: открытый ключ избирателя
        :return:
        """

        # подписывает личность и открытый ключ избирателя
        signature = rsa.sign((voter_identity + str(voter_public_key.n)).encode(), self.private_key, 'MD5')

        return {
            "identity": voter_identity,
            "public_key": voter_public_key,
            "signature": signature,
        }
