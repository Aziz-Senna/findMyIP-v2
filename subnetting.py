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
        #(fonction d'Amine ben hadou)
        masques = NetworkCalculator.generer_donnees_masques()
        return masques[prefixe - 8]["decimal"]

    #les vérifications
    @staticmethod
    def decouper_sous_reseaux(ip,nb_sr):
        ip = ip.strip()
        
        # Contrôle 1: L'IP doit être valide (fonction d'Amine ben hadou)
        if not NetworkCalculator.verifier_ip(ip):
            return None, "Adresse IP invalide."
            
        # Contrôle 2: Le nombre de SR doit être un entier d'au moins 2
        try:
            nb_sr = int(nb_sr)
        except ValueError:
            return None, "Le nombre de SR doit être un nombre entier."
        if nb_sr < 2:
            return None, "Le nombre de SR doit être au moins 2."
        
        # Contrôle 3 : classe et masque de classe (obtenir_masque_classe de network.py)
        classe, masque_classe = NetworkCalculator.obtenir_masque_classe(ip)
        if masque_classe == "N/A":
            return None, f"Classe {classe} : pas de découpe possible."
        prefixe_classe = masque_classe.count("255") * 8

        # Contrôle 4 : réseau de départ (calculer_ids_reseau de network.py)
        res, err = NetworkCalculator.calculer_ids_reseau(ip, masque_classe)
        if err:
            return None, err
        reseau_depart = res["reseau_classful"]

        # Étape E : nombre de plis (bits empruntés) et nouveau préfixe
        bits = SubnetCalculator.calculer_bits_empruntes(nb_sr)
        nouveau_prefixe = prefixe_classe + bits 
        # a partir de /31 n'y a plus d'espace 
        if nouveau_prefixe > 30:
            return None, "Impossible : trop de sous-réseaux pour cette classe."
        
        # Étape F : taille d'un SR, nouveau masque, max machines /19
        #32 − 19 = 13, puis 2¹³ → 8192
        taille_sr = 2 ** (32 - nouveau_prefixe)
        nouveau_masque = SubnetCalculator.prefixe_vers_masque(nouveau_prefixe)
        max_machines = taille_sr - 2

        # Étape G : on découpe les morceaux un par un
        nb_sr_reels = 2 ** bits
        debut = SubnetCalculator.ip_vers_entier(reseau_depart)
        sous_reseaux = []

        # On ne calcule que les 256 premiers SR : au-delà, la liste serait
        # trop longue pour être affichée (ex : 4 millions de SR en classe A)
        # et la fenêtre se figerait. Le résumé, lui, reste complet.
        nb_affiches = min(nb_sr_reels, 256)
        for i in range(nb_affiches):
            adresse_reseau = debut + i * taille_sr
            broadcast = adresse_reseau + taille_sr - 1
            sous_reseaux.append({
                "numero": i + 1,
                "reseau": SubnetCalculator.entier_vers_ip(adresse_reseau),
                "premiere": SubnetCalculator.entier_vers_ip(adresse_reseau + 1),
                "derniere": SubnetCalculator.entier_vers_ip(broadcast - 1),
                "broadcast": SubnetCalculator.entier_vers_ip(broadcast),
            })

        # Résultat final : le résumé + la liste des sous-réseaux
        resultat = {
            "classe": classe,
            "reseau": reseau_depart,
            "masque_classe": masque_classe,
            "nb_sr_demandes": nb_sr,
            "bits_empruntes": bits,
            "nouveau_prefixe": nouveau_prefixe,
            "nouveau_masque": nouveau_masque,
            "nb_sr_reels": nb_sr_reels,
            "max_machines": max_machines,
            "sous_reseaux": sous_reseaux,
            "nb_sr_affiches": nb_affiches,       # combien de SR sont dans la liste
        }
        return resultat, None
    

    
    

    
        
if __name__ == "__main__":
    print("--- Résultat final ---")
    res, err = SubnetCalculator.decouper_sous_reseaux("192.168.1.50", "4")
    print("Réseau :", res["reseau"])
    print("Nouveau masque :", res["nouveau_masque"])
    print("Max machines :", res["max_machines"])
    for sr in res["sous_reseaux"]:
        print(sr["numero"], sr["reseau"], sr["premiere"], sr["derniere"], sr["broadcast"])