import tkinter as tk
from tkinter import messagebox, ttk
from database import Database
from network import NetworkCalculator
from datetime import datetime

class LoginWindow:

    def __init__(self, root):
        self.root = root
        self.root.title("FINDMYIP - Connexion")
        self.root.geometry("400x600")
        self.root.configure(bg="#f4f7f9")
        self.root.resizable(False, False)

        # Titre
        tk.Label(self.root, text="Connexion", font=("Segoe UI", 20, "bold"), 
                 bg="#f4f7f9", fg="#2c3e50").pack(pady=20)

        try:
            self.image = tk.PhotoImage(file="icons.png").subsample(2, 2)
            tk.Label(self.root, image=self.image, bg="#f4f7f9").pack(pady=10)
        except:
            pass

        # Champs
        container = tk.Frame(self.root, bg="#f4f7f9")
        container.pack(pady=10, padx=40, fill="x")

        tk.Label(container, text="Nom d'utilisateur", bg="#f4f7f9", font=("Segoe UI", 10)).pack(anchor="w")
        self.username_entry = tk.Entry(container, font=("Segoe UI", 11))
        self.username_entry.pack(fill="x", pady=(5, 15))

        tk.Label(container, text="Mot de passe", bg="#f4f7f9", font=("Segoe UI", 10)).pack(anchor="w")
        self.password_entry = tk.Entry(container, show="*", font=("Segoe UI", 11))
        self.password_entry.pack(fill="x", pady=5)

        self.btn_show = tk.Button(container, text="Afficher le mot de passe", command=self.toggle_password,
                                  relief="flat", bg="#f4f7f9", fg="#3498db", font=("Segoe UI", 9))
        self.btn_show.pack(anchor="e")

        tk.Button(self.root, text="SE CONNECTER", command=self.validate_connexion,
                  bg="#2ecc71", fg="white", font=("Segoe UI", 12, "bold"), 
                  relief="flat", cursor="hand2", height=2).pack(pady=20, padx=40, fill="x")

    def toggle_password(self):
        if self.password_entry.cget("show") == "*":
            self.password_entry.config(show="")
            self.btn_show.config(text="Masquer le mot de passe")
        else:
            self.password_entry.config(show="*")
            self.btn_show.config(text="Afficher le mot de passe")

    def validate_connexion(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if Database.check_login(username, password):
            role = Database.check_login(username , password)
            self.execute_dashbord(role)
        else:
            messagebox.showerror("Erreur", "Identifiants incorrects")

    def execute_dashbord(self, role):
        for widget in self.root.winfo_children():
            widget.destroy()
        FindMyIPApp(self.root, role)

class FindMyIPApp:
    def __init__(self, root, role="user"):
        self.root = root
        self.root.title("FINDMYIP - Dashboard")
        self.root.geometry("800x600")
        self.root.configure(bg="#f4f7f9")
        self.role = role

        # Configuration du style
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Segoe UI", 10), padding=10)
        
        self.setup_main_menu()

    def setup_main_menu(self):
        tk.Label(self.root, text="FINDMYIP", font=("Segoe UI", 24, "bold"), 
                 bg="#f4f7f9", fg="#2c3e50").pack(pady=30)
        
        # Grille pour les boutons
        container = tk.Frame(self.root, bg="#f4f7f9")
        container.pack(expand=True)

        buttons = [
            ("Générateur de Masques", self.open_generator),
            ("Validateur Format IP", self.open_validator),
            ("Analyseur de Propriétés", self.open_analysor),
            ("Masque de Classe", self.open_class_mask),
            ("Réseau & Sous-Réseau", self.open_subnetting),
            ("Vérificateur Connexion", self.open_comm),
            ("Infos Application", self.open_informations), 
            ("Se déconnecter", self.close_connexion)
        ]
        
        if self.role == "admin":
            buttons.insert(6,("Ajouter un Utilisateur", self.open_add_user))

        for i, (text, func) in enumerate(buttons):
            row, col = divmod(i, 2)
            btn = tk.Button(container, text=text, command=func, width=28, height=2,
                           bg="#ffffff", fg="#34495e", font=("Segoe UI", 10),
                           relief="flat", cursor="hand2", bd=1)
            btn.grid(row=row, column=col, padx=15, pady=10)
            # Petit effet au survol
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg="#ecf0f1"))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg="#ffffff"))

    # --- ACTIONS ---

    def open_generator(self):
        win = tk.Toplevel(self.root)
        win.title("Tableau des Masques")
        win.geometry("900x600")
        
        donnees = NetworkCalculator.generate_datas_masks()
        
        # Affichage dans un tableau (Treeview) pour que ce soit pro
        cols = ("prefixe", "decimal", "binaire")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        tree.heading("prefixe", text="CIDR")
        tree.heading("decimal", text="Masque Décimal")
        tree.heading("binaire", text="Masque Binaire")
        
        for d in donnees:
            tree.insert("", "end", values=(d["prefixe"], d["decimal"], d["binaire"]))
        
        tree.pack(expand=True, fill="both", padx=10, pady=10)

    def open_validator(self):
        win = tk.Toplevel(self.root)
        win.title("Validateur de Format IP")
        win.geometry("400x200")
        tk.Label(win, text="Entrez une adresse IP :").pack(pady=10)
        ent_ip = tk.Entry(win); ent_ip.pack()
        lbl_res = tk.Label(win, text="", pady=20)
        lbl_res.pack()
        def validate():
            ip = ent_ip.get()
            if NetworkCalculator.check_ip(ip) == "True":
                lbl_res.config(text=f"{ip} est une adresse IP valide.", fg="green")
            else:
                #On récupère l'erreur.
                lbl_res.config(text=f"{NetworkCalculator.check_ip(ip)}", fg="red")

        tk.Button(win, text="Valider", command=validate).pack(pady=10)

    def open_analysor(self):
        win= tk.Toplevel(self.root)
        win.title("Analyseur de Propriétés")
        win.geometry("400x300")
        tk.Label(win, text="Entrez une adresse IP :").pack(pady=10)
        ent_ip = tk.Entry(win); ent_ip.pack()
        lbl_res = tk.Label(win, text="", pady=20)
        lbl_res.pack()
        def analyse():
            ip = ent_ip.get()
            if ip and NetworkCalculator.check_ip(ip) == "True":
                res = NetworkCalculator.analyse_ip(ip)
                msg = f"Classe : {res['classe']}\nType : {res['type']}\nÉtat : {res['status']}"
                lbl_res.config(text=msg, fg="blue")
            else:
                lbl_res.config(text=f"{ip} n'est pas une adresse IP valide.", fg="red")
        tk.Button(win, text="Analyser", command=analyse).pack(pady=10)
        
    def open_class_mask(self):
        win= tk.Toplevel(self.root)
        win.title("Masque de Classe")
        win.geometry("400x200")
        tk.Label(win, text="Entrez une adresse IP :").pack(pady=10)
        ent_ip = tk.Entry(win); ent_ip.pack()
        lbl_res = tk.Label(win, text="", pady=20)
        lbl_res.pack()
        def get():
            ip = ent_ip.get()
            if ip and NetworkCalculator.check_ip(ip) == "True":
                classe, masque = NetworkCalculator.get_mask_class(ip)
                lbl_res.config(text=f"Classe : {classe}\nMasque par défaut : {masque}", fg="blue")
            else:
                lbl_res.config(text=f"{ip} n'est pas une adresse IP valide.", fg="red")     
        tk.Button(win, text="Obtenir Masque", command=get).pack(pady=10)

    #AMBZ 01 
    def open_subnetting(self):
        win = tk.Toplevel(self.root)
        win.title("ID Réseau & Sous-Réseau")
        win.geometry("400x300")
        
        tk.Label(win, text="IP:").pack(pady=5)
        ent_ip = tk.Entry(win); ent_ip.pack()
        tk.Label(win, text="Masque:").pack(pady=5)
        ent_m = tk.Entry(win); ent_m.pack()
        
        lbl_res = tk.Label(win, text="", pady=20)
        lbl_res.pack()

        def calculate():
            #AMBZ 01
            #Si le format de l'adresse IP est correct
            if NetworkCalculator.check_ip(ent_ip.get()) == "True":
                res, err = NetworkCalculator.compute_adress_network(ent_ip.get(), ent_m.get())
                if err: messagebox.showerror("Erreur", err)
                else:
                    txt = f"Réseau Classfull : {res['reseau_classfull']}\nSous-Réseau : {res['sous_reseau']}"
                    lbl_res.config(text=txt, fg="blue")
            else:
                err = messagebox.showerror("Erreur", NetworkCalculator.check_ip(ent_ip.get()))
        tk.Button(win, text="Calculer", command=calculate).pack()

    def open_comm(self):
        win = tk.Toplevel(self.root)
        win.title("Test de Communication")
        win.geometry("450x400")
        
        tk.Label(win, text="Machine 1 IP / Masque").pack()
        e1_ip = tk.Entry(win); e1_ip.pack()
        e1_m = tk.Entry(win); e1_m.pack()
        
        tk.Label(win, text="\nMachine 2 IP / Masque").pack()
        e2_ip = tk.Entry(win); e2_ip.pack()
        e2_m = tk.Entry(win); e2_m.pack()
        
        lbl_res = tk.Label(win, text="", pady=20, font=("Arial", 10, "bold"))
        lbl_res.pack()

        def test():
            res, err = NetworkCalculator.test_communication(e1_ip.get(), e1_m.get(), e2_ip.get(), e2_m.get())
            if err: lbl_res.config(text=err, fg="red")
            else:
                m1_voit_m2, m2_voit_m1 = res
                status = "Communication Possible ✅" if (m1_voit_m2 and m2_voit_m1) else "Problème de Routage ⚠️"
                color = "green" if (m1_voit_m2 and m2_voit_m1) else "orange"
                lbl_res.config(text=f"M1 -> M2: {m1_voit_m2}\nM2 -> M1: {m2_voit_m1}\n\n{status}", fg=color)

        tk.Button(win, text="Vérifier", command=test, bg="#2980b9", fg="white").pack(pady=10)

    def open_add_user(self):
        win = tk.Toplevel(self.root)
        win.title("Ajouter un Utilisateur")
        win.geometry("400x300")
        win.configure(bg="#f4f7f9")
        win.resizable(False, False)
        tk.Label(win, text="Ajouter un Utilisateur", font=("Segoe UI", 16, "bold"),
             bg="#f4f7f9", fg="#2c3e50").pack(pady=20)

        container = tk.Frame(win, bg="#f4f7f9")
        container.pack(pady=10, padx=40, fill="x")

        tk.Label(container, text="Nom d'utilisateur", bg="#f4f7f9", font=("Segoe UI", 10)).pack(anchor="w")
        ent_user = tk.Entry(container, font=("Segoe UI", 11))
        ent_user.pack(fill="x", pady=(5, 15))

        tk.Label(container, text="Mot de passe", bg="#f4f7f9", font=("Segoe UI", 10)).pack(anchor="w")
        ent_pwd = tk.Entry(container, show="*", font=("Segoe UI", 11))
        ent_pwd.pack(fill="x", pady=5)

        #AMBZ 01
        def is_date(pwd):
            try:
                #Si aucune exception n'a ete attrape alors il s'agit d'une date.
                datetime.strptime(pwd, "%d/%m/%Y")
                return True
            except ValueError:
                return False
        #AMBZ 01
        def contains_space(pwd):
            for i in range (len(pwd)):
                if(pwd[i] == chr(32)):
                    return True
            return False

        #AMBZ 01
        def contains_special_characters(pwd):
            #Ajoute tous les caractères spéciaux dans une liste.
            special_characters = {chr(i) for r in (range(33, 48), range(58, 65), range(91, 97)) for i in r}

            #Source : https://www.askpython.com/python/set/python-sets-resolving-typeerror
            special_characters = list(special_characters)        
            respect_conditions_caracters = False

            #Vérification des caractères spéciaux
            for i in range(len(pwd)):
                for j in range (len(special_characters)):
                    if(pwd[i] == special_characters[j]):
                        respect_conditions_caracters = True
            return respect_conditions_caracters
        
        def save():
            user = ent_user.get().strip()
            pwd = ent_pwd.get()

            if user and pwd:
                #Vérification du mot de passe 
                if (len(pwd))< 8:
                    messagebox.showerror("Erreur", "Le mot de passe n'est pas assez long.\n" \
                    "La taille du mdp doit être supérieur ou égal à 8.")

                elif (contains_space(pwd)) == True:
                    messagebox.showerror("Erreur", "Le mot de passe ne doit pas contenir d'espace.")

                elif (pwd.isdigit()) == True or (pwd.isalpha()) == True or (contains_special_characters(pwd)) == False:
                    messagebox.showerror("Erreur", 
                        "Le mot de passe doit contenir des chiffres, des lettres et des caractères spéciaux.")

                elif is_date(pwd) == True:
                    messagebox.showerror("Erreur","Le mot de passe ne doit pas être une date de naissance.")

                else:
                    #On teste l'enregistrement d'utilisateur
                    if Database.save_user(user, pwd):
                        Database.save_user(user, pwd)
                        messagebox.showinfo("Succès", "Utilisateur enregistré !")
                        win.destroy()
                    else:
                        messagebox.showerror("Erreur", "Échec de l'enregistrement.")
            else:
                messagebox.showwarning("Attention", "Remplis tous les champs.")

        tk.Button(win, text="AJOUTER", command=save,
              bg="#2ecc71", fg="white", font=("Segoe UI", 12, "bold"),
              relief="flat", cursor="hand2", height=2).pack(pady=20, padx=40, fill="x")
        

    def open_informations(self):
        fenetre_info = tk.Toplevel(self.root)
        fenetre_info.title("Spécifications Techniques")
        fenetre_info.geometry("700x700")
        
        texte_complet = (
            "les infos sur l'application\n"
            "" + "="*60 + "\n\n"
            "1. TABLEAU DES MASQUES :\n"
            "   Afficher tous les masques de /8 à /30 sous 3 formes :\n"
            "   -> Notation CIDR (ex: /24)\n"
            "   -> Binaire (ex: 11111111.11111111.11111111.00000000)\n"
            "   -> Décimal pointé (ex: 255.255.255.0)\n\n"
            "2. VALIDATION DE FORMAT :\n"
            "   Déterminer si une adresse IP entrée au clavier est valide\n\n"
            "3. ANALYSE DES PROPRIÉTÉS :\n"
            "   Déterminer la CLASSE (A, B, C, D, E) et préciser s'il s'agit d'une :\n"
            "   -> Adresse RÉSERVÉE (ex: 127.0.0.1)\n"
            "   -> Adresse PRIVÉE (ex: 192.168.x.x)\n\n"
            "4. MASQUE DE CLASSE :\n"
            "   Donner le masque par défaut (Classful) selon la classe de l'IP.\n\n"
            "5. RÉSEAU ET SOUS-RÉSEAU :\n"
            "   calculate l'ID Réseau et l'ID Sous-réseau à partir de l'IP et du masque.\n\n"
            "6. VÉRIFICATION BILATÉRALE :\n"
            "   Déterminer si 2 IPs sont dans le même réseau :\n"
            "   -> Test A voit B : (IP_B appartient au réseau de A)\n"
            "   -> Test B voit A : (IP_A appartient au réseau de B)\n\n"
            "7. Ajouter un utilisateur :\n"
            "   -> Entrer les informations de l'utilisateur\n"
            "   -> validate les informations\n"
        )

        label_cadre = tk.Label(fenetre_info, text=texte_complet, justify="left", 
                              font=("Courier New", 10), padx=20, pady=20, bg="white", relief="sunken")
        label_cadre.pack(expand=True, fill="both", padx=10, pady=10)
        tk.Button(fenetre_info, text="Compris", command=fenetre_info.destroy).pack(pady=10)

    #AMBZ 01
    def close_connexion(self):
        win = tk.Toplevel(self.root)
        win.resizable(False, False)
        win.title("Déconnexion")
        win.geometry("450x200")

        #AMBZ 01
        def logout():
            if (Database.check_logout()):
                Database.check_logout()
                for widget in self.root.winfo_children():
                    widget.destroy()
                self.root.destroy()
                LoginWindow(tk.Tk())             
            else:
                messagebox.showerror("Erreur", "Impossible de se déconnecter.")

        tk.Label(win, text="Êtes vous sûr de vouloir se déconnecter ?", font=("Segoe UI", 16, "bold"),
                     bg="#f4f7f9", fg="#2c3e50").pack(pady=20)

        frame = tk.Frame(win)
        frame.pack(padx=10)

        tk.Button(frame, text="Oui", command=logout
            ,bg="#2ecc71", fg="white", font=("Segoe UI", 12, "bold"), width=5, height=2).pack(side="left", padx=10)

        tk.Button(frame, text="Non", command=win.destroy 
            ,bg="#cc2e2e", fg="white", font=("Segoe UI", 12, "bold"), width=5, height=2).pack(side="left", padx=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = LoginWindow(root)
    root.mainloop()