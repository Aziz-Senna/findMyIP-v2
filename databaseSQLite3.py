import sqlite3
import os.path
import bcrypt

class Database:
    #Amine Bouaziz
    @staticmethod
    def get_db_connection():
        if(os.path.isfile("FINDMYIP.db") == False):
            return Database.create_db()
        return sqlite3.connect("FINDMYIP.db")

    #Amine Bouaziz
    @staticmethod
    def create_db():
        conn = sqlite3.connect("FINDMYIP.db")
        cursor = conn.cursor()

        create_table_query = """create table if not exists userInfo(
            nameUser varchar(100) not null, 
            passwordUser varchar(100) not null, 
            role varchar(100) not null default ('user'), 
            primary key (nameUser))"""
        cursor.execute(create_table_query)
        cursor.execute("insert into userInfo values (?,?,?)", 
            ('firstadmin', '$2b$12$9bKppilobc0wqkG9VnjZ3uHjOqbRNT8C8TCeckF/OodN49peqRl.W', 'admin'))
        conn.commit()

    #Amine Bouaziz
    @staticmethod
    def check_login(username , password):
        try :
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            #query = "SELECT passwordUser, role FROM userInfo WHERE nameUser = %s"
            query = "select passwordUser, role from userInfo where nameUser = " + username
            
            #cursor.execute(query, (username,))
            cursor.execute(query)

            result = cursor.fetchone()
            hashed_from_db = result[0]
            role = result[1]

            if result:
                hashed_from_db = result[0]
                if isinstance(hashed_from_db, str):
                    hashed_from_db = hashed_from_db.encode('utf-8')
                
                if(bcrypt.checkpw(password.encode('utf-8'), hashed_from_db)):
                    return role
            return False
        except Exception as e:
            print(f"erreur de connexion: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.cursor():
                conn.close()
                #cursor.close()

    #Amine Bouaziz
    @staticmethod
    def enregister_user(username , password):
        try : 
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            #query = "INSERT INTO userInfo (nameUser, passwordUser) VALUES (%s, %s)"
            #cursor.execute(query, (username, hashed_password))
            cursor.execute("insert into userInfo (nameUser, passwordUser) values (?,?)", (username, hashed_password))
            conn.commit()
            return True
        except Exception as e:
            print(f"erreur d'enregistrement: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.cursor():
                conn.close()
                cursor.close()