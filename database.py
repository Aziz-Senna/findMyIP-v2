import sqlite3
import os.path
import bcrypt
from datetime import datetime, timedelta

class Database:

    __isLoggIn = False
    __current_user = None

    #AMBZ 02
    #Date : 06/10/2026
    #During : 30minutes
    @staticmethod
    def get_db_connection():
        if (os.path.isfile("FINDMYIP.db") == False):
            Database.create_db()
        Database.__isLoggIn = True
        return sqlite3.connect("FINDMYIP.db")

    #AMBZ 02
    #Date : 06/10/2026
    #During : 10minutes
    @staticmethod
    def create_db():
        conn = sqlite3.connect("FINDMYIP.db")
        cursor = conn.cursor()

        #AMBZ 02
        #Date : 29/10/2026
        #Update of the table
        create_user_table_query = """create table if not exists userInfo(
            idUser integer primary key autoincrement,
            nameUser varchar(20) not null, 
            passwordUser varchar(100) not null, 
            role varchar(5) not null)"""
        cursor.execute(create_user_table_query)
        cursor.execute("insert into userInfo (nameUser, passwordUser, role) values (?, ?, ?)", 
            ('firstadmin', '$2b$12$9bKppilobc0wqkG9VnjZ3uHjOqbRNT8C8TCeckF/OodN49peqRl.W', 'admin'))
        conn.commit()




        #AMBZ 02
        #Date : 29/10/2026
        create_feature_table_query = """create table if not exists features(
            idFeature integer primary key autoincrement,
            nameFeature varchar(30) not null)"""

        cursor.execute(create_feature_table_query)
        cursor.execute("insert into features (nameFeature) values (?)", ('Générateur de Masques',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Validateur Format IP',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Analyseur de Propriétés',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Réseau & Sous-Réseau',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Découpe en Sous-Réseaux',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Vérificateur Connexion',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Infos Application',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Se déconnecter',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Ajouter un utilisateur',))
        conn.commit()

        cursor.execute("insert into features (nameFeature) values (?)", ('Supprimer un utilisateur',))
        conn.commit()

        create_connexion_query = """create table if not exists connexion(
            idConnexion integer primary key autoincrement, 
            dateLogin datetime not null, 
            dateLogout datetime not null)"""

        cursor.execute(create_connexion_query)
        conn.commit()

        cursor.execute("alter table connexion add column fkIdUser integer not null references userInfo(idUser)")
        conn.commit()





        create_used_table_query = """create table if not exists used(
            dateOfUse datetime not null, 
            entry1 varchat(25) not null, 
            entry2 varchar(25) not null, 
            entry3 varchar(25), 
            entry4 varchar(25),
            primary key(dateOfUse))"""

        cursor.execute(create_used_table_query)
        conn.commit()

        cursor.execute("alter table used add column fkIdUser integer not null references userInfo(idUser)")
        conn.commit()

        cursor.execute("alter table used add column fkIdFeature integer not null references features(idFeature)")
        conn.commit()

        cursor.execute("insert into used (dateOfUse, entry1, entry2, fkIdUser, fkIdFeature) values (?,?,?,?,?)", 
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "192.168.15.2", "255.255.255.0", 1, 4))
        conn.commit()
        cursor.close()
        conn.close()      

    #AMBZ 02 
    #Date : 07/10/2026
    #During : 30minutes
    @staticmethod
    def check_login(username , password):
        try :
            conn = Database.get_db_connection()
            cursor = conn.cursor()

            #J'ai juste changé le %s à la fin de la requête query par ?
            query = "select passwordUser, role from userInfo where nameUser = ?"           
            cursor.execute(query, (username,))

            result = cursor.fetchone()
            hashed_from_db = result[0]
            role = result[1]

            if result:
                hashed_from_db = result[0]
                if isinstance(hashed_from_db, str):
                    hashed_from_db = hashed_from_db.encode('utf-8')
                
                if(bcrypt.checkpw(password.encode('utf-8'), hashed_from_db)):
                    Database.__current_user = username
                    return role                
            return False
        except Exception as e:
            print(f"erreur de connexion: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.cursor():
                #Il fallait inverser l'ordre de fermeture entre conn et cursor.
                cursor.close()
                conn.close()

    @staticmethod
    def get_current_user():
        return Database.__current_user
                

    #AMBZ 02
    #Date : 07/10/2026
    #During : 2h
    @staticmethod
    def save_user(username, role, password):
        try : 
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            cursor.execute("insert into userInfo (nameUser, role, passwordUser) values (?,?,?)", (username, role, hashed_password))
            conn.commit()
            return True
        except Exception as e:
            print(f"erreur d'enregistrement: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.cursor():
                #Il fallait inverser l'ordre de fermeture entre conn et cursor.
                cursor.close()
                conn.close()

    def get_users():
        conn = Database.get_db_connection()
        cursor = conn.cursor()
        query = "select nameUser, role from userInfo where nameUser not like ?"
        cursor.execute(query, (Database.get_current_user(),))
        return cursor.fetchall()  
    
    def nb_users():
        conn = Database.get_db_connection()
        cursor = conn.cursor()
        query = "select count(nameUser) from userInfo where nameUser not like ?"
        cursor.execute(query, (Database.get_current_user(),))
        nb_users = cursor.fetchone()
        return nb_users[0]

    #AMBZ 02
    #Date : 28/10/2026
    #During : 10minutes
    @staticmethod
    def delete_user(user_to_delete):
        try:
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            query = "delete from userInfo where nameUser like ?"
            cursor.execute(query, (Database.get_users()[user_to_delete][0],))
            conn.commit()
            return True
        except Exception as e:
            print(f"erreur de suppression: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.cursor():
                #Il fallait inverser l'ordre de fermeture entre conn et cursor.
                cursor.close()
                conn.close()        

    #AMBZ 02
    #Date : 13/10/2026
    #During : 10minutes
    @staticmethod
    def check_logout():
        if(Database.__isLoggIn == False):
           return False
        Database.__isLoggIn = False
        return True

    #yazan 01
    #Date : 31/10/2026
    @staticmethod
    # Tâche 3 : crée la table qui garde la recette de chaque découpe en sous-réseaux.
    # Créée ici et pas dans create_db, car create_db ne s'exécute que si le
    def create_addressing_table():
        conn = Database.get_db_connection()
        cursor = conn.cursor()
        # idAddressing : numéro qui se remplit tout seul (1, 2, 3...)
        # network      : réseau de départ, ex 172.16.0.0
        # mask         : nouveau masque des sous-réseaux, ex 255.255.224.0
        # nbSubnets    : nombre de sous-réseaux demandés par l'utilisateur
        # maxHosts     : nombre de machines utilisables par sous-réseau
        # modifiedBy   : utilisateur connecté qui a fait l'enregistrement
        # modifiedDate : date et heure, remplies automatiquement par SQLite
        cursor.execute("""create table if not exists addressing_table(
            idAddressing integer primary key autoincrement,
            network varchar(15) not null,
            mask varchar(15) not null,
            nbSubnets integer not null,
            maxHosts integer not null,
            modifiedBy varchar(100) not null,
            modifiedDate text not null default (datetime('now', 'localtime')))""")
        conn.commit()
        cursor.close()
        conn.close()

    @staticmethod
    # écrit une ligne dans la table d'adressage.
    # Renvoie True si l'enregistrement a réussi, False sinon.
    def save_subnetting(network, mask, nb_subnets, max_hosts):
        try:
            #On s’assure que la page existe.C’est une sécurité.
            Database.create_addressing_table()
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""insert into addressing_table
                (network, mask, nbSubnets, maxHosts, modifiedBy)
                values (?, ?, ?, ?, ?)""",
                (network, mask, nb_subnets, max_hosts, Database.get_current_user()))
            conn.commit()
            return True
        except Exception as e:
            print(f"erreur d'enregistrement de la découpe: {e}")
            return False
        #si c raté ou pas 
        finally:
            if 'conn' in locals():
                cursor.close()
                conn.close()

    