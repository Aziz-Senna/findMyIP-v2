class NetworkCalculator:
    
    @staticmethod
    def generate_datas_masks():
        list_masques = []
        
        for i in range(8, 31):
            binary_mask = ""
            decimal_parts = [0, 0, 0, 0]
            for bit in range(32):
                if bit < i:
                    decimal_parts[bit//8] += 2**(7-(bit%8))
                    binary_mask += "1"
                else:
                    binary_mask += "0"
                
                if (bit+1)%8 == 0 and bit < 31:
                    binary_mask += "."
                
            list_masques.append({
                "prefixe": f"/{i:02d}",
                "binaire": binary_mask,
                "decimal": ".".join(str(part) for part in decimal_parts)
            })
        return list_masques

    #AMBZ 01
    #Initialement, la méthode retourne un bool mais on retourne plutôt l'erreur en string.
    @staticmethod
    def check_ip(ip_input):
        ip = ip_input.strip().replace(" ", "")
        if len(ip) < 7 or len(ip) > 15:
            return "La taille de l'adresse IP n'est pas correcte."
        bytes = ip.split(".")
        
        if len(bytes) != 4:
            return "L'adresse IP doit contenir quatre octets soit quatre parties décimales."        
        try:
            for o in bytes:
                if not o.isdigit():
                    return "Un des octets n'est pas décimal."
                value = int(o)
                #Pas de value < 0 car la methode isdigit() ne considère pas les négatives comme des chiffres dû au caractère -.
                if value > 255:
                    return "La valeur d'un des octets n'est pas comprise entre 0 et 255."
                if len(o) > 1 and o[0] == '0':
                    return "Les octets du style 0xx ne sont pas acceptés."
            return "True"
        except ValueError:
            return "False"
        
    @staticmethod
    def analyse_ip(ip_input):
        bytes = [int(o) for o in ip_input.split(".")]
        first = bytes[0]
        second = bytes[1]
        
        # Détermination de la classe
        if 0 <= first <= 127:
            class_adress = "Classe A"
        elif 128 <= first <= 191:
            class_adress = "Classe B"
        elif 192 <= first <= 223:
            class_adress = "Classe C"
        elif 224 <= first <= 239:
            class_adress = "Classe D"
        else:
            class_adress = "Classe E"

        # Privée ou Publique
        type_ip = "Publique"
        if (first == 10) or \
           (first == 172 and 16 <= second <= 31) or \
           (first == 192 and second == 168):
            type_ip = "Privée"

        # Réservée ou non
        status = "Non réservée"
        if first == 0 or first == 127 or first >= 255:
            status = "Réservée"

        return {
            "classe": class_adress,
            "type": type_ip,
            "status": status
        }
    
    @staticmethod
    def get_mask_class(ip_input):
        try:
            bytes = ip_input.split(".")
            first_byte = int(bytes[0])
            
            if 0 <= first_byte <= 127:
                return "A", "255.0.0.0"
            elif 128 <= first_byte <= 191:
                return "B", "255.255.0.0"
            elif 192 <= first_byte <= 223:
                return "C", "255.255.255.0"
            elif 224 <= first_byte <= 239:
                return "D (Multicast)", "N/A"
            elif 240 <= first_byte <= 255:
                return "E (Expérimentale)", "N/A"
            else:
                return "Invalide", "Inconnu"
        except (ValueError, IndexError):
            return "Erreur", "Format invalide"
    
    @staticmethod
    def compute_adress_network(ip_input, mask_input):
        try:
            ip_bytes = [int(i) for i in ip_input.split(".")]
            mask_bytes = [int(m) for m in mask_input.split(".")]

            first = ip_bytes[0]
            if 0 <= first <= 127:
                classe, m_class = "A", [255, 0, 0, 0]
            elif 128 <= first <= 191:
                classe, m_class = "B", [255, 255, 0, 0]
            elif 192 <= first <= 223:
                classe, m_class = "C", [255, 255, 255, 0]
            else:
                return None, "Classe spéciale (D/E) sans masque standard."

            # Réseau classfull 
            net_id = ".".join(str(ip_bytes[i] & m_class[i]) for i in range(4))
            
            # Sous-réseau 
            subnet_id = ".".join(str(ip_bytes[i] & mask_bytes[i]) for i in range(4))

            return {
                "classe": classe,
                "reseau_classful": net_id,
                "sous_reseau": subnet_id
            }, None        
        except Exception as e:
            return None, f"Erreur de calcul : {e}"
        
    @staticmethod
    def test_communication(ip1_s, mask1_s, ip2_s, mask2_s):
        try:
            i1 = [int(i) for i in ip1_s.split(".")]
            m1 = [int(m) for m in mask1_s.split(".")]
            i2 = [int(i) for i in ip2_s.split(".")]
            m2 = [int(m) for m in mask2_s.split(".")]

            m1_voit_m2 = all((i1[i] & m1[i]) == (i2[i] & m1[i]) for i in range(4))
            
            m2_voit_m1 = all((i2[i] & m2[i]) == (i1[i] & m2[i]) for i in range(4))

            return (m1_voit_m2, m2_voit_m1), None
        except:
            return None, "Erreur de format"