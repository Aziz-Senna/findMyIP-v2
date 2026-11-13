from network import NetworkCalculator

class SubnetCalculator:

    # Calculs pour la découpe en sous-réseaux (sans librairie IP).
    # Méthodes statiques : on les appelle directement sur la classe,
    @staticmethod
    def ip_into_natural(ip):
        # Transforme une IP en un seul grand number.
        # "172.16.0.0" -> [172, 16, 0, 0] -> 172×256³ + 16×256² + 0×256 + 0
        bytes = [int(o) for o in ip.split(".")]
        return bytes[0] * 256**3 + bytes[1] * 256**2 + bytes[2] * 256 + bytes[3]

    @staticmethod
    def natural_into_ip(number):
        # Chemin inverse : on divise par 256 (//) puis on garde le reste (%)
        byte1 = (number // 256**3) % 256
        byte2 = (number // 256**2) % 256
        byte3 = (number // 256) % 256
        byte4 = number % 256
        return f"{byte1}.{byte2}.{byte3}.{byte4}"

    @staticmethod
    def calculate_bits_boworred(nb_sr):
        # Plus petit number de bits tel que 2^bits >= number de SR demandés
        bits = 0
        while 2 ** bits < nb_sr:
            bits += 1
        return bits

    #sr
    @staticmethod
    def prefix_into_mask(prefix):
        masks = NetworkCalculator.generate_datas_masks()
        return masks[prefix - 8]["decimal"]

    #les vérifications
    @staticmethod
    def slice_under_network(ip,nb_sr):
        ip = ip.strip()
        
        # Contrôle 1 : l'IP doit être valide (check_ip de network.py)
        # check_ip renvoie le texte "True" si l'IP est bonne, sinon le message d'erreur
        check = NetworkCalculator.check_ip(ip)
        if check != "True":
            return None, check
        
        # Contrôle 2: Le number de SR doit être un entier d'au moins 2
        try:
            nb_sr = int(nb_sr)
        except ValueError:
            return None, "Le number de SR doit être un number entier."
        if nb_sr < 2:
            return None, "Le number de SR doit être au moins 2."
        
        # Contrôle 3 : classe et masque de classe (obtenir_class_mask de network.py)
        classe, class_mask = NetworkCalculator.get_mask_class(ip)
        if class_mask == "N/A":
            return None, f"Classe {classe} : pas de découpe possible."
        prefix_class = class_mask.count("255") * 8

        # Contrôle 4 : réseau de départ (calculer_ids_network de network.py)
        res, err = NetworkCalculator.compute_adress_network(ip, class_mask)
        if err:
            return None, err
        first_network = res["network_classfull"]

        # Étape E : number de plis (bits empruntés) et nouveau préfixe
        bits = SubnetCalculator.calculate_bits_boworred(nb_sr)
        new_prefix = prefix_class + bits 
        # a partir de /31 n'y a plus d'espace 
        if new_prefix > 30:
            return None, "Impossible : trop de sous-réseaux pour cette classe."
        
        # Étape F : size d'un SR, nouveau masque, max machines /19
        #32 − 19 = 13, puis 2¹³ → 8192
        size_sr = 2 ** (32 - new_prefix)
        new_mask = SubnetCalculator.prefix_into_mask(new_prefix)
        max_machines = size_sr - 2

        # Étape G : on découpe les morceaux un par un
        nb_sr_reels = 2 ** bits
        first = SubnetCalculator.ip_into_natural(first_network)
        under_network = []

        # On ne calcule que les 256 premiers SR : au-delà, la liste serait
        # trop longue pour être affichée (ex : 4 millions de SR en classe A)
        # et la fenêtre se figerait. Le résumé, lui, reste complet.
        nb_showed = min(nb_sr_reels, 256)
        for i in range(nb_showed):
            adress_network = first + i * size_sr
            broadcast = adress_network + size_sr - 1
            under_network.append({
                "number": i + 1,
                "network": SubnetCalculator.natural_into_ip(adress_network),
                "first": SubnetCalculator.natural_into_ip(adress_network + 1),
                "last": SubnetCalculator.natural_into_ip(broadcast - 1),
                "broadcast": SubnetCalculator.natural_into_ip(broadcast),
            })

        # Résultat final : le résumé + la liste des sous-réseaux
        result = {
            "classe": classe,
            "network": first_network,
            "class_mask": class_mask,
            "nb_sr_asked": nb_sr,
            "bits_boworred": bits,
            "new_prefix": new_prefix,
            "new_mask": new_mask,
            "nb_sr_reels": nb_sr_reels,
            "max_machines": max_machines,
            "under_network": under_network,
            "nb_sr_showed": nb_showed,       # combien de SR sont dans la liste
        }
        return result, None