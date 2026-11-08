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
        self.root.protocol("WM_DELETE_WINDOW", self.close_programm)       

        # Configuration du style
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Segoe UI", 10), padding=10)
        
        Database.save_connexion("login")        
        self.setup_main_menu()
    # Bouton de sécurité (admins seulement) : demande ou confirmation
    # du changement de mot de passe obligatoire pour tous les utilisateurs.
    def open_security_button(self):
        # On demande d'abord confirmation : c'est une action importante
        ok = messagebox.askyesno("Sécurité",
            "En cas de vol de la base de données, cette action oblige TOUS les "
            "utilisateurs à changer leur mot de passe à leur prochaine connexion.\n\n"
            "Elle doit être validée par 2 administrateurs différents.\n\n"
            "Voulez-vous continuer ?")
        if not ok:
            return
        # on demande a security.py de tainter le clic
        success , message = SecurityManager.security_button()
        if success:
            messagebox.showinfo("Sécuité",message)
        else:
            messagebox.showerror("Sécuité",message)


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
        
        donnees = NetworkCalculator.generate_datas_masks()
        
        # Affichage dans un grid_usersau (Treeview) pour que ce soit pro
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
            Database.save_activity(ip, None, None, None, 2)
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
            Database.save_activity(ip, None, None, None, 3)
            
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
            Database.save_activity(ip, None, None, None, 4)
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
            #Si le format de l'adresse IP est correct
            if NetworkCalculator.check_ip(ent_ip.get()) == "True":
                res, err = NetworkCalculator.compute_adress_network(ent_ip.get(), ent_m.get())
                if err: messagebox.showerror("Erreur", err)
                else:
                    txt = f"Réseau Classfull : {res['reseau_classfull']}\nSous-Réseau : {res['sous_reseau']}"
                    lbl_res.config(text=txt, fg="blue")
            else:
                err = messagebox.showerror("Erreur", NetworkCalculator.check_ip(ent_ip.get()))
            Database.save_activity(ent_ip.get(), ent_m.get(), None, None, 5)
        tk.Button(win, text="Calculer", command=calculate).pack()

    # Tâche 3 : fenêtre de découpe en sous-réseaux
    def open_decoupe(self):
        # Nouvelle fenêtre par-dessus le menu principal
        # 850 de large pour les 5 colonnes, 600 de haut pour le résumé + le tableau
        win = tk.Toplevel(self.root)
        win.title("Découpe en Sous-Réseaux")
        win.geometry("850x600")

        # Champ 1 : l'adresse IP
        tk.Label(win, text="Adresse IP :").pack(pady=5)
        ent_ip = tk.Entry(win)
        ent_ip.pack()

        # Champ 2 : le nombre de sous-réseaux
        tk.Label(win, text="Nombre de sous-réseaux :").pack(pady=5)
        ent_nb = tk.Entry(win)
        ent_nb.pack()

        # Ce qui se passe quand on clique sur "Découper"
        def decouper():
            # On envoie les 2 champs à la calculatrice de subnetting.py
            res, err = SubnetCalculator.decouper_sous_reseaux(ent_ip.get(), ent_nb.get())
            # Tâche 6 : on garde ce que l'utilisateur a tapé (fonctionnalité n°6)
            Database.save_activity(ent_ip.get(), ent_nb.get(), None, None, 6)
            if err:
                # Problème : on affiche le message et on s'arrête là
                messagebox.showerror("Erreur", err, parent=win)
                return

            # Tout va bien : on écrit le résumé dans le label
            texte = (
                f"Classe : {res['classe']}\n"
                f"Réseau de départ : {res['reseau']}\n"
                f"Masque de classe : {res['masque_classe']}\n"
                f"Bits empruntés : {res['bits_empruntes']}\n"
                f"Nouveau masque : {res['nouveau_masque']} (/{res['nouveau_prefixe']})\n"
                f"SR demandés : {res['nb_sr_demandes']}\n"
                f"SR créés : {res['nb_sr_reels']}\n"
                f"Machines par SR : {res['max_machines']}"
            )
            # Si la liste a été coupée (trop de SR), on le signale
            if res["nb_sr_affiches"] < res["nb_sr_reels"]:
                texte += f"\n⚠ Affichage limité aux {res['nb_sr_affiches']} premiers SR"
            lbl_resume.config(text=texte)

            # On vide le tableau, au cas où une découpe était déjà affichée
            for ligne in tree.get_children():
                tree.delete(ligne)
            # On ajoute une ligne par sous-réseau
            for sr in res["sous_reseaux"]:
                tree.insert("", "end", values=(sr["numero"], sr["reseau"],
                                               sr["premiere"], sr["derniere"], sr["broadcast"]))

            # Tâche 3 : on enregistre la "recette" de la découpe dans addressing_table
            if not Database.save_subnetting(res["reseau"], res["nouveau_masque"],
                                            res["nb_sr_demandes"], res["max_machines"]):
                messagebox.showerror("Erreur", "La découpe n'a pas pu être enregistrée.", parent=win)

        # Le bouton qui lance la découpe
        tk.Button(win, text="Découper", command=decouper,
                  bg="#2980b9", fg="white").pack(pady=10)

        # Zone où le résumé s'affichera (vide au départ)
        lbl_resume = tk.Label(win, text="", fg="blue", justify="left")
        lbl_resume.pack(pady=5)

        # Tableau des sous-réseaux (vide au départ, rempli par decouper())
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
            Database.save_activity(e1_ip.get(), e1_m.get(), e2_ip.get(), e2_m.get(), 7)

        tk.Button(win, text="Vérifier", command=test, bg="#2980b9", fg="white").pack(pady=10)

    def handle_users(self):
        win = tk.Toplevel(self.root)
        win.resizable(False, False)
        win.title("Gestion des utilisateurs")
        win.geometry("500x300")

        def open_add_user():
            if Database.nb_users() == pow(9,4):
                messagebox.showerror("Erreur", "Impossible d'ajouter un nouvel utilisateur, la capacité maximale (6561) est atteinte.")
                return
            
            win = tk.Toplevel(self.root)
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
            v.set(None) # initialiser
            tk.Label(container, text="Type d'utilisateur", bg="#f4f7f9", font=("Segoe UI", 10)).pack(anchor="w", pady=(5,15))
            tk.Radiobutton(container, text="Admin", variable=v, value="admin", bg="#f4f7f9").pack(side="left", padx=10, pady=5)
            tk.Radiobutton(container, text="User", variable=v, value="user", bg="#f4f7f9").pack(side="left", pady=5)

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
                        if Database.save_user(user, v.get(), pwd):
                            Database.save_user(user, v.get(), pwd)
                            messagebox.showinfo("Succès", "Utilisateur enregistré !")
                            win.destroy()
                        else:
                            messagebox.showerror("Erreur", "Échec de l'enregistrement.")
                else:
                    messagebox.showwarning("Attention", "Remplis tous les champs.")
        
            tk.Button(win, text="AJOUTER", command=save,
                    bg="#2ecc71", fg="white", font=("Segoe UI", 12, "bold"),
                    relief="flat", cursor="hand2", height=2).pack(pady=20, padx=40, fill="x")

        def open_delete_user(users = None):
            if Database.nb_users() == 0:
                messagebox.showerror("Erreur !", "Il n'y a aucun utilisateur à supprimer !")
                return

            if users is None:
                users = Database.get_users()
            win = tk.Toplevel(self.root)
            win.title("Supprimer un utilisateur")
            win.geometry("700x500")
            win.configure(bg="#f4f7f9")
            win.resizable(True, True)
            win.grid_columnconfigure(0, weight=1)

            MAX_VISIBLE = 6   # nombre de lignes visibles sans défiler

            # Style commun à toutes les cellules
            cell_style = dict(bg="#f4f7f9", fg="#2c3e50", font=("Segoe UI", 12, "bold"),
                            width=15, height=2, borderwidth=1, relief="solid")

            def set_value(value):
                user_to_delete.set(value)
                user_selected.config(text=f"Vous avez sélectionné : {users[value][0]}")

            def delete():
                index = user_to_delete.get()
                if index == -1:
                    messagebox.showwarning("Attention", "Sélectionne un utilisateur.")
                    return
                if Database.delete_user(index):
                    messagebox.showinfo("Succès !", "Utilisateur supprimé !")
                    win.destroy()
                else:
                    messagebox.showerror("Erreur", "Échec de la suppression.")

            def research():                
                if Database.research_user(search_entry.get()) == [] :
                    messagebox.showerror("Erreur", "Utilisateur introuvable !")
                    return
                users = Database.research_user(search_entry.get())  
                win.destroy()
                open_delete_user(users) 

            def to_filter(event):
                if Database.filter(type_role.get()) == False:
                    messagebox.showerror("Erreur", "Le filtre n'a pas pu s'effectuer.")
                    return
                if type_role.get() == 'Tous':
                    users = Database.get_users()
                else:
                    users = Database.filter(type_role.get())
                win.destroy()
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
        fenetre_info = tk.Toplevel(self.root)
        fenetre_info.title("Spécifications Techniques")
        fenetre_info.geometry("700x700")
        
        texte_complet = (
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
        Database.save_activity(None, None, None, None, 8)
        label_cadre = tk.Label(fenetre_info, text=texte_complet, justify="left", 
                              font=("Courier New", 10), padx=20, pady=20, bg="white", relief="sunken")
        label_cadre.pack(expand=True, fill="both", padx=10, pady=10)
        tk.Button(fenetre_info, text="Compris", command=fenetre_info.destroy).pack(pady=10)

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