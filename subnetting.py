from network import NetworkCalculator 


class SubnetCalculator:
    # Calculs pour la découpe en sous-réseaux (sans librairie IP).
    # Méthodes statiques : on les appelle directement sur la classe,
    @staticmethod
    def ip_vers_entier(ip):
        # Transforme une IP en un seul grand nombre.
        # "172.16.0.0" -> [172, 16, 0, 0] -> 172×256³ + 16×256² + 0×256 + 0
        octets = [int(o) for o in ip.split(".")]
        return octets[0] * 256**3 + octets[1] * 256**2 + octets[2] * 256 + octets[3]

    @staticmethod
    def entier_vers_ip(nombre):
        # Chemin inverse : on divise par 256 (//) puis on garde le reste (%)
        octet1 = (nombre // 256**3) % 256
        octet2 = (nombre // 256**2) % 256
        octet3 = (nombre // 256) % 256
        octet4 = nombre % 256
        return f"{octet1}.{octet2}.{octet3}.{octet4}"

    @staticmethod
    def calculer_bits_empruntes(nb_sr):
        # Plus petit nombre de bits tel que 2^bits >= nombre de SR demandés
        bits = 0
        while 2 ** bits < nb_sr:
            bits += 1
        return bits
    #sr
    @staticmethod
    def prefixe_vers_masque(prefixe):
        masques = NetworkCalculator.generer_donnees_masques()
        return masques[prefixe - 8]["decimal"]



if __name__ == "__main__":
    n = SubnetCalculator.ip_vers_entier("172.16.0.0")
    print(n)                                          # 2886729728
    print(SubnetCalculator.entier_vers_ip(n))         # 172.16.0.0
    print(SubnetCalculator.entier_vers_ip(n + 8192))  # 172.16.32.0

    print(SubnetCalculator.calculer_bits_empruntes(5))    # 3
    print(SubnetCalculator.calculer_bits_empruntes(100))  # 7


