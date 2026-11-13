import tkinter as tk
from tkinter import messagebox, ttk
from database import Database
from network import NetworkCalculator
from subnetting import SubnetCalculator
from datetime import datetime
from security import SecurityManager

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

        tk.Label(container, text="Matricule de l'utilisateur", bg="#f4f7f9", font=("Segoe UI", 10)).pack(anchor="w")
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
        id_number = self.username_entry.get().strip()
        password = self.password_entry.get()
        role = Database.check_login(id_number , password)

        if role:
            # Bouton de sécurité : si l'étiquette vaut 1, on oblige à changer de mot de passe AVANT d'accéder au menu (ce n'est pas un blocage)
            if SecurityManager.must_change_password(id_number):
                self.open_change_password(role)
            else:
                self.execute_dashbord(role)
        else:
            messagebox.showerror("Erreur", "Identifiants incorrects")

    # Fenêtre affichée après le bouton de sécurité : l'utilisateur doit choisir un nouveau mot de passe avant d'arriver au menu.
    def open_change_password(self, role):
        win = tk.Toplevel(self.root)
        win.title("Nouveau mot de passe obligatoire")
        win.geometry("400x350")
        win.configure(bg="#f4f7f9")
        win.resizable(False, False)
        win.grab_set()   # on ne peut plus cliquer sur la fenêtre de connexion derrière

        tk.Label(win, text="Par mesure de sécurité,\nvous devez changer votre mot de passe.",
                 font=("Segoe UI", 11, "bold"), bg="#f4f7f9", fg="#2c3e50").pack(pady=20)

        tk.Label(win, text="Nouveau mot de passe", bg="#f4f7f9").pack()
        ent_new = tk.Entry(win, show="*", font=("Segoe UI", 11))
        ent_new.pack(pady=5)

        tk.Label(win, text="Confirmer le mot de passe", bg="#f4f7f9").pack()
        ent_confirm = tk.Entry(win, show="*", font=("Segoe UI", 11))
        ent_confirm.pack(pady=5)

        def validate():
            new_pwd = ent_new.get()
            # Vérifications de base sur le nouveau mot de passe
            if new_pwd != ent_confirm.get():
                messagebox.showerror("Erreur", "Les deux mots de passe ne sont pas identiques.", parent=win)
            elif len(new_pwd) < 8:
                messagebox.showerror("Erreur", "Le mot de passe doit faire au moins 8 caractères.", parent=win)
            elif " " in new_pwd or new_pwd.isdigit() or new_pwd.isalpha():
                messagebox.showerror("Erreur",
                    "Le mot de passe doit contenir des lettres et des chiffres, sans espace.", parent=win)
            else:
                # On enregistre le nouveau mot de passe.
                success, message = SecurityManager.change_password(new_pwd)
                if success:
                    messagebox.showinfo("Succès", message, parent=win)
                    win.destroy()
                    self.execute_dashbord(role)
                else:
                    messagebox.showerror("Erreur", message, parent=win)

        tk.Button(win, text="VALIDER", command=validate, bg="#2ecc71", fg="white",
                  font=("Segoe UI", 12, "bold"), relief="flat").pack(pady=20)

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
        self.root.protocol("WM_DELETE_WINDOW", self.close_programm)       

        # Configuration du style
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Segoe UI", 10), padding=10)
        
        Database.save_connexion("login")        
        self.setup_main_menu()

    # Bouton de sécurité (admins seulement) : demande ou confirmation du changement de mot de passe obligatoire pour tous les utilisateurs.
    def open_security_button(self):
        # On demande d'abord confirmation : c'est une action importante
        ok = messagebox.askyesno("Sécurité",
            "En cas de vol de la base de données, cette action oblige TOUS les "
            "utilisateurs à changer leur mot de passe à leur prochaine connexion.\n\n"
            "Elle doit être validée par 2 administrateurs différents.\n\n"
            "Voulez-vous continuer ?")
        if not ok:
            return
        
        success , message = SecurityManager.security_button()
        if success:
            messagebox.showinfo("Sécurité",message)
        else:
            messagebox.showerror("Sécurité",message)

    def setup_main_menu(self):
        tk.Label(self.root, text="FINDMYIP", font=("Segoe UI", 24, "bold"), 
                 bg="#f4f7f9", fg="#2c3e50").pack(pady=(30, 10))

        # Ergonomie : carte qui montre avec quel compte on est connecté
        user_card = tk.Frame(self.root, bg="#ffffff", highlightbackground="#dfe6e9",
                             highlightthickness=1, padx=15, pady=8)
        user_card.pack(pady=(0, 10))

        # L'icône
        tk.Label(user_card, text="👤", font=("Segoe UI", 20), bg="#ffffff").pack(side="left")

        # Le nom (en gras) et le matricule (en gris)
        tk.Label(user_card, text=Database.get_current_username(),
                 font=("Segoe UI", 11, "bold"), bg="#ffffff", fg="#2c3e50").pack(side="left", padx=(8, 4))
        tk.Label(user_card, text=f"·  {Database.get_current_user()}",
                 font=("Segoe UI", 10), bg="#ffffff", fg="#7f8c8d").pack(side="left")

        # Le badge du rôle : rouge pour admin, bleu pour user
        couleur_role = "#e74c3c" if self.role == "admin" else "#3498db"
        tk.Label(user_card, text=self.role.upper(), font=("Segoe UI", 9, "bold"),
                 bg=couleur_role, fg="white", padx=8, pady=2).pack(side="left", padx=(15, 0))
        
        
        # Grille pour les boutons
        container = tk.Frame(self.root, bg="#f4f7f9")
        container.pack(expand=True)

        buttons = [
            ("Générateur de Masques", self.open_generator),
            ("Validateur Format IP", self.open_validator),
            ("Analyseur de Propriétés", self.open_analysor),
            ("Masque de Classe", self.open_class_mask),
            ("Réseau & Sous-Réseau", self.open_subnetting),
            ("Découpe en Sous-Réseaux", self.open_decoupe),
            ("Vérificateur Connexion", self.open_comm),
            ("Infos Application", self.open_informations), 
            ("Se déconnecter", self.close_connexion)
        ]
        
        if self.role == "admin":
            buttons.insert(6,("Gestion des utilisateurs", self.handle_users))
            buttons.insert(7,("Sécurité: changer tous les mdp", self.open_security_button))

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
    #Enregistrer la date et heure déconnexion et fermer le programme.
    def close_programm(self):        
            Database.save_connexion("logout")
            for widget in self.root.winfo_children():
                widget.destroy()
            self.root.quit()

    def open_generator(self):
        win = tk.Toplevel(self.root)
        win.title("Tableau des masques")
        win.geometry("900x600")        
        datas = NetworkCalculator.generate_datas_masks()
        Database.save_masks(datas)
        Database.save_activity(None, None, None, None, "Générateur de Masques")
        
        # Affichage dans un grid_users (Treeview)
        cols = ("prefixe", "decimal", "binaire")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        tree.heading("prefixe", text="CIDR")
        tree.heading("decimal", text="Masque Décimal")
        tree.heading("binaire", text="Masque Binaire")        
        for data in datas:
            tree.insert("", "end", values=(data["prefixe"], data["decimal"], data["binaire"]))        
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
            Database.save_activity(ip, None, None, None, "Validateur Format IP")
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
            Database.save_activity(ip, None, None, None, "Analyseur de Propriétés")
            
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
            Database.save_activity(ip, None, None, None, "Masque de Classe")
        tk.Button(win, text="Obtenir Masque", command=get).pack(pady=10)

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
            # Si le format de l'adresse IP est correct
            if NetworkCalculator.check_ip(ent_ip.get()) == "True":
                res, err = NetworkCalculator.compute_adress_network(ent_ip.get(), ent_m.get())
                if err: messagebox.showerror("Erreur", err)
                else:
                    txt = f"Réseau Classfull : {res['network_classfull']}\nSous-Réseau : {res['under_network']}"
                    lbl_res.config(text=txt, fg="blue")

            # Sinon la méthode retourne le type d'erreur.
            else:
                err = messagebox.showerror("Erreur", NetworkCalculator.check_ip(ent_ip.get()))
            Database.save_activity(ent_ip.get(), ent_m.get(), None, None, "Réseau & Sous-Réseau")
        tk.Button(win, text="Calculer", command=calculate).pack()

    def open_decoupe(self):
        win = tk.Toplevel(self.root)
        win.title("Découpe en Sous-Réseaux")
        win.geometry("850x600")

        tk.Label(win, text="Adresse IP :").pack(pady=5)
        ent_ip = tk.Entry(win)
        ent_ip.pack()

        tk.Label(win, text="Nombre de sous-réseaux :").pack(pady=5)
        ent_nb = tk.Entry(win)
        ent_nb.pack()

        # On teste le découpage en sous-réseaux.
        def slice():

            res, err = SubnetCalculator.slice_under_network(ent_ip.get(), ent_nb.get())
            Database.save_activity(ent_ip.get(), ent_nb.get(), None, None,"Découpe en Sous-Réseaux")
            if err:
                # Problème : on affiche le message et on s'arrête là
                messagebox.showerror("Erreur", err, parent=win)
                return

            text_label = (
                f"Classe : {res['classe']}\n"
                f"Réseau de départ : {res['network']}\n"
                f"Masque de classe : {res['class_mask']}\n"
                f"Bits empruntés : {res['bits_boworred']}\n"
                f"Nouveau masque : {res['new_mask']} (/{res['new_prefix']})\n"
                f"SR demandés : {res['nb_sr_asked']}\n"
                f"SR créés : {res['nb_sr_reels']}\n"
                f"Machines par SR : {res['max_machines']}"
            )

            # Si la liste a été coupée (trop de SR), on le signale
            if res["nb_sr_showed"] < res["nb_sr_reels"]:
                texte += f"\n⚠ Affichage limité aux {res['nb_sr_showed']} premiers SR"
            lbl_resume.config(text=text_label)

            # On vide le tableau, au cas où une découpe était déjà affichée
            for ligne in tree.get_children():
                tree.delete(ligne)

            # On ajoute une ligne par sous-réseau
            for sr in res["under_network"]:
                tree.insert("", "end", values=(sr["number"], sr["network"],
                                               sr["first"], sr["last"], sr["broadcast"]))

            if not Database.save_subnetting(res["network"], res["new_mask"],
                                            res["nb_sr_asked"], res["max_machines"]):
                messagebox.showerror("Erreur", "La découpe n'a pas pu être enregistrée.", parent=win)

        tk.Button(win, text="Découper", command=slice,
                  bg="#2980b9", fg="white").pack(pady=10)

        lbl_resume = tk.Label(win, text="", fg="blue", justify="left")
        lbl_resume.pack(pady=5)

        # Tableau des sous-réseaux (vide au départ, rempli par slice())
        cols = ("numero", "reseau", "premiere", "derniere", "broadcast")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        tree.heading("numero", text="SR")
        tree.heading("reseau", text="Adresse réseau")
        tree.heading("premiere", text="1re machine")
        tree.heading("derniere", text="Dernière machine")
        tree.heading("broadcast", text="Broadcast")
        tree.column("numero", width=50, anchor="center")

        # Barre de défilement reliée au tableau (posée AVANT le tableau,
        # sinon le tableau prend toute la place et la barre n'a plus d'espace)
        scrollbar = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y", pady=10)
        tree.pack(expand=True, fill="both", padx=10, pady=10)
        

    def open_comm(self):
        win = tk.Toplevel(self.root)
        win.title("Test de Communication")
        win.geometry("450x550")
        
        tk.Label(win, text="Machine 1 IP / Masque").pack()
        e1_ip = tk.Entry(win); e1_ip.pack()
        e1_m = tk.Entry(win); e1_m.pack()
        
        tk.Label(win, text="\nMachine 2 IP / Masque").pack()
        e2_ip = tk.Entry(win); e2_ip.pack()
        e2_m = tk.Entry(win); e2_m.pack()
        
        lbl_res = tk.Label(win, text="", pady=20, font=("Arial", 10, "bold"))
        lbl_res.pack()

        def get_network(ip,masque):
            r , e  = NetworkCalculator.compute_adress_network(ip,masque)
            return r["under_network"] if r else "?"

        # L'action de vérification entre deux réseaux et leurs masques.
        def test():
            ip1, m1 = e1_ip.get(), e1_m.get()
            ip2, m2 = e2_ip.get(), e2_m.get()
            res, err = NetworkCalculator.test_communication(ip1,m1,ip2,m2)
            if err: lbl_res.config(text=err, fg="red")
            else:
                m1_see_m2, m2_see_m1 = res

                # Les 4 réseaux : chaque machine fait le calcul avec SON masque
                net_m1_by_m1 = get_network(ip1, m1)   
                net_m2_by_m1 = get_network(ip2, m1)   
                net_m2_by_m2 = get_network(ip2, m2)   
                net_m1_by_m2 = get_network(ip1, m2)   

                text_complete = (
                    f"Vue de M1 (masque {m1}) :\n"
                    f"   réseau de M1 : {net_m1_by_m1}\n"
                    f"   réseau de M2 : {net_m2_by_m1}\n"
                    f"   → M1 voit M2 : {'oui ✅' if m1_see_m2 else 'non ❌'}\n\n"
                    f"Vue de M2 (masque {m2}) :\n"
                    f"   réseau de M2 : {net_m2_by_m2}\n"
                    f"   réseau de M1 : {net_m1_by_m2}\n"
                    f"   → M2 voit M1 : {'oui ✅' if m2_see_m1 else 'non ❌'}"
                )

                # Le résultat selon les 3 cas possibles
                if m1_see_m2 and m2_see_m1:
                    text_complete += "\n\n✅ Communication possible :\nles deux machines sont dans le même réseau."
                    color = "green"
                elif not m1_see_m2 and not m2_see_m1:
                    text_complete += ("\n\n❌ Problème de routage : réseaux différents.\n"
                              "Les deux machines ne sont pas dans le même réseau,\n"
                              "il faut passer par un routeur.")
                    color = "red"
                else:
                    text_complete += ("\n\n⚠ Problème de routage : masques différents.\n"
                              "Une machine voit l'autre, mais pas l'inverse.\n"
                              "Les deux machines doivent avoir le même masque.")
                    color = "orange"

                # On affiche tout, avec la couleur choisie
                lbl_res.config(text=text_complete, fg=color, justify="left")

            # On enregistre ce que l'utilisateur a tapé
            Database.save_activity(ip1, m1, ip2, m2, "Vérificateur Connexion")
        tk.Button(win, text="Vérifier", command=test, bg="#2980b9", fg="white").pack(pady=10)

    # Gère la gestion des utilisateurs (ajout et suppression).
    def handle_users(self):
        win = tk.Toplevel(self.root)
        win.resizable(False, False)
        win.title("Gestion des utilisateurs")
        win.geometry("500x300")

        # Efface tous les objets de la fenêtre pour éviter d'en créer une nouvelle pour ainsi redémarrer sur une page blanche.
        def clear_window():
            for widget in win.winfo_children():
                widget.destroy()

        # Gère l'ajout avec toutes les informations essentielles à demander.
        def open_add_user():
            if Database.nb_users() == pow(9,4):
                messagebox.showerror("Erreur", "Impossible d'ajouter un nouvel utilisateur, la capacité maximale (6561) est atteinte.")
                return
            
            clear_window()
            win.title("Ajouter un utilisateur")
            win.geometry("400x500")
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

            v = tk.StringVar()
            v.set(None) # initialiser la valeur par défaut du radio bouton et la transforme en String.
            tk.Label(container, text="Type d'utilisateur", bg="#f4f7f9", font=("Segoe UI", 10)).pack(anchor="w", pady=(5,15))
            tk.Radiobutton(container, text="Admin", variable=v, value="admin", bg="#f4f7f9").pack(side="left", padx=10, pady=5)
            tk.Radiobutton(container, text="User", variable=v, value="user", bg="#f4f7f9").pack(side="left", pady=5)

            id_number = Database.create_id_number()

            def is_date(pwd):
                try:
                    #Si aucune exception n'a ete attrape alors il s'agit d'une date.
                    datetime.strptime(pwd, "%d/%m/%Y")
                    return True
                except ValueError:
                    return False
                
            def contains_space(pwd):
                for i in range (len(pwd)):
                    if(pwd[i] == chr(32)):
                        return True
                return False

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

            # Sauvegarde l'utiliasateur dans la base de données.
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
                        if Database.save_user(id_number, user, v.get(), pwd):
                            Database.save_user(id_number, user, v.get(), pwd)
                            messagebox.showinfo("Succès", "Utilisateur enregistré !")
                            win.destroy()
                        else:
                            messagebox.showerror("Erreur", "Échec de l'enregistrement.")
                else:
                    messagebox.showwarning("Attention", "Remplis tous les champs.")
        
            tk.Button(win, text="AJOUTER", command=save,
                    bg="#2ecc71", fg="white", font=("Segoe UI", 12, "bold"),
                    relief="flat", cursor="hand2", height=2).pack(pady=20, padx=40, fill="x")
            tk.Label(win, text=f"Voici votre matricule, veuillez le mémoriser : {id_number}",
                fg="#2980b9", bg="#f4f7f9", font=("Segoe UI", 10, "bold")).pack(fill="x", padx=40)

        # Gère la suppression avec toutes les informations essentielles à afficher sauf le mot de passe !!!!!!!!!!!!! (même s'il est haché comme un steak)
        def open_delete_user(users = None):
            if Database.nb_users() == 0:
                messagebox.showerror("Erreur !", "Il n'y a aucun utilisateur à supprimer !")
                return

            if users is None:
                users = Database.get_users()

            clear_window()
            win.title("Supprimer un utilisateur")
            win.geometry("700x500")
            win.configure(bg="#f4f7f9")
            win.resizable(False, False)
            win.grid_columnconfigure(0, weight=1)

            # Nombre de lignes visibles sans défiler dans le tableau.
            # S'il y a plus de MAX_VISIBLE users, alors il y aura une side bar.
            MAX_VISIBLE = 6

            # Style commun à toutes les cellules
            cell_style = dict(bg="#f4f7f9", fg="#2c3e50", font=("Segoe UI", 12, "bold"),
                            width=15, height=2, borderwidth=1, relief="solid")

            # Définir la valeur de la cellule par le matricule de l'utilisateur.
            def set_value(value):
                user_to_delete.set(value)
                user_selected.config(text=f"Vous avez sélectionné : {users[value][0]}")

            # L'action de supprimer un utilisateur dans la base de données.
            def delete():
                index = user_to_delete.get()
                if index == -1:
                    messagebox.showwarning("Attention", "Sélectionne un utilisateur.")
                    return
                
                # On vérifie qu'on a le droit de supprimer (règle des 2 admins minimum)
                ok, message = SecurityManager.can_delete_user(users[index][0])
                if not ok:
                    messagebox.showerror("Suppression impossible", message, parent=win)
                    return
                
                if Database.delete_user(index):
                    messagebox.showinfo("Succès !", "Utilisateur supprimé !")
                    win.destroy()
                else:
                    messagebox.showerror("Erreur", "Échec de la suppression.")

            # L'action de rechercher un utilisateur via son matricule.
            def research():                
                if Database.research_user(search_entry.get()) == [] :
                    messagebox.showerror("Erreur", "Utilisateur introuvable !")
                    return
                users = Database.research_user(search_entry.get())
                open_delete_user(users) 

            # L'action de filtrer la liste d'utilisateur en fonction du rôle (tous-admin-user).
            def to_filter(event):
                if Database.filter(type_role.get()) == False:
                    messagebox.showerror("Erreur", "Le filtre n'a pas pu s'effectuer.")
                    return
                if type_role.get() == 'Tous':
                    users = Database.get_users()
                else:
                    users = Database.filter(type_role.get())
                open_delete_user(users)

            # L'indice de l'utilisateur à supprimer (-1 = aucun)
            user_to_delete = tk.IntVar(value=-1)

            # ---------- Conteneur du grid_users----------
            grid_users = tk.Frame(win, bg="#f4f7f9")
            grid_users.grid(row=0, column=0)

            # ---------- Recherche (label + input) au-dessus du tableau ----------
            search_frame = tk.Frame(grid_users, bg="#f4f7f9")
            search_frame.grid(row=0, column=0, padx=0, sticky="w", pady=(15))

            tk.Label(search_frame, text="Recherchez un utilisateur :", font=("Segoe UI", 8, "bold"),
                        bg="#f4f7f9", fg="#2c3e50").grid(row=0, column=0, padx=(0, 0))

            search_var = tk.StringVar()
            search_entry = tk.Entry(search_frame, textvariable=search_var, font=("Segoe UI", 8),
                                    width=5, relief="solid", borderwidth=1)
            search_entry.grid(row=0, column=1, ipady=3)
            search_entry.focus_set()
            tk.Button(search_frame, text="Rechercher", font=("Segoe UI", 8, "bold"), command=research).grid(row=0, column=2, padx=10)

            # ---------- Filtrage des utilisateurs ----------
            tk.Label(search_frame, text="Filtre des utilisateurs :", font=("Segoe UI", 8, "bold"),
                bg="#f4f7f9", fg="#2c3e50").grid(row=0, column=3, padx=(80, 10))            

            type_role = tk.StringVar()
            filter = ttk.Combobox(search_frame, textvariable=type_role)
            filter['values'] = ['Tous', 'admin', 'user']
            filter.grid(row=0, column=4)
            filter.bind('<<ComboboxSelected>>', to_filter)

            # Titres (fixes, ne défilent pas)
            header = tk.Frame(grid_users, bg="#f4f7f9")
            header.grid(row=1, column=0, sticky="w")
            header_labels = []
            for col, titre in enumerate(["Index", "Matricule", "Nom d'utilisateur", "Rôle"]):
                lbl = tk.Label(header, text=titre, **cell_style)
                lbl.grid(row=0, column=col)
                header_labels.append(lbl)

            # Zone défilante : Canvas + Scrollbar
            canvas = tk.Canvas(grid_users, bg="#f4f7f9", highlightthickness=0)
            scrollbar = tk.Scrollbar(grid_users, orient="vertical", command=canvas.yview)
            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.grid(row=2, column=0, sticky="nsew")
            scrollbar.grid(row=2, column=1, sticky="ns")

            # Le Frame qui contient les lignes, placé DANS le canvas
            grid_users = tk.Frame(canvas, bg="#f4f7f9")
            canvas.create_window((0, 0), window=grid_users, anchor="nw")

            # Met à jour la zone de défilement quand le contenu change de taille
            grid_users.bind("<Configure>",
                            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

            # ---------- Lignes ----------
            for row_user in range(len(users)):
                cell = tk.Frame(grid_users, bg="#f4f7f9", borderwidth=1, relief="solid")
                cell.grid(row=row_user, column=0, sticky="nsew")

                tk.Button(cell, command=lambda i=row_user: set_value(i), bg="#2c3e50",
                        borderwidth=0, relief="flat", activebackground="#3F5B4B",
                        cursor="hand2").place(relx=0.5, rely=0.5, anchor="center",
                                                width=18, height=18)

                tk.Label(grid_users, text=users[row_user][0], **cell_style).grid(
                    row=row_user, column=1, sticky="nsew")
                tk.Label(grid_users, text=users[row_user][1], **cell_style).grid(
                    row=row_user, column=2, sticky="nsew")
                tk.Label(grid_users, text=users[row_user][2], **cell_style).grid(
                                    row=row_user, column=3, sticky="nsew")

            # ---------- Dimensions ----------
            win.update_idletasks()
            # Colonnes alignées sur les titres (la colonne Index n'a pas de texte pour se dimensionner)
            for col, lbl in enumerate(header_labels):
                grid_users.grid_columnconfigure(col, minsize=lbl.winfo_reqwidth())
            win.update_idletasks()

            row_height = grid_users.grid_bbox(0, 0)[3]
            visible = min(len(users), MAX_VISIBLE)
            canvas.configure(width=grid_users.winfo_reqwidth(), height=row_height * visible)

            if len(users) > MAX_VISIBLE:
                # Défilement à la molette n'importe où dans la fenêtre
                win.bind("<MouseWheel>",
                        lambda e: canvas.yview_scroll(int(-e.delta / 120), "units"))
            else:
                scrollbar.grid_remove()   # pas besoin de scrollbar

            # ---------- Bas de la fenêtre ----------
            user_selected = tk.Label(win, text="", fg="blue", bg="#f4f7f9")
            user_selected.grid(row=2, column=0, pady=15)

            tk.Button(win, text="SUPPRIMER", command=delete, bg="#cc2e2e", fg="white",
                    font=("Segoe UI", 12, "bold"), width=15, height=2).grid(
                        row=3, column=0, padx=10, pady=5)

        frame = tk.Frame(win)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(frame, text="Que voulez-vous faire ?", font=("Segoe UI", 16, "bold"),
                     bg="#f4f7f9", fg="#2c3e50").grid(row=1, pady=20)

        tk.Button(frame, text="Ajouter un utilisateur", command=open_add_user
            ,bg="#2980b9", fg="white", font=("Segoe UI", 12, "bold"), width=20, height=2).grid(row=2, pady=20)

        tk.Button(frame, text="Supprimer un utilisateur", command=open_delete_user 
            ,bg="#2980b9", fg="white", font=("Segoe UI", 12, "bold"), width=20, height=2).grid(row=3)
        

    def open_informations(self):
        window_info = tk.Toplevel(self.root)
        window_info.title("Spécifications Techniques")
        window_info.geometry("700x700")
        
        text_complete = (
            "Les infos sur l'application\n"
            "" + "="*60 + "\n\n"
            "1. grid_usersAU DES MASQUES :\n"
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
            "   Donner le masque par défaut (Classfull) selon la classe de l'IP.\n\n"
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
        Database.save_activity(None, None, None, None, "Infos Application")
        label_cadre = tk.Label(window_info, text=text_complete, justify="left", 
                              font=("Courier New", 10), padx=20, pady=20, bg="white", relief="sunken")
        label_cadre.pack(expand=True, fill="both", padx=10, pady=10)
        tk.Button(window_info, text="Compris", command=window_info.destroy).pack(pady=10)

    def close_connexion(self):
        win = tk.Toplevel(self.root)
        win.resizable(False, False)
        win.title("Déconnexion")
        win.geometry("450x200")

        def logout():
            if (Database.check_logout()):
                Database.check_logout()
                Database.save_connexion('logout')
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
