import sys

from certifying_authority import CertifyingAuthority
from ballot_distributor import BallotDistributor
from voter import Voter

if __name__ == "__main__":
    CA = CertifyingAuthority()
    BD = BallotDistributor()
    V = Voter()

    certificate = CA.issue_certificate(V.identity, V.public_key)

    serial_number = BD.generate_serial_number()
    BD.save_serial_number_and_voter_identity(serial_number, V.identity)
    ballot = BD.get_ballot(serial_number)
    ballot_signature = ballot['signature']
    encrypted_ballot = BD.encrypt_ballot(ballot, V.public_key)

    decrypted_ballot = V.decrypt_ballot(encrypted_ballot)

    # TODO: не передавать подпись бюллетеня отдельно
    is_correct = V.check_ballot(decrypted_ballot, ballot_signature, BD.public_key)
    if not is_correct:
        print('Бюллетень испорчен.')
        sys.exit()
    serial_number = decrypted_ballot.get('serial_number')
    print(serial_number)
