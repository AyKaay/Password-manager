import sqlite3
import nacl.secret
import nacl.utils
from hashlib import sha256

# TODO Create GUI for the PWM

connection = sqlite3.connect("passworddatabase.db")
cursor = connection.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS passworddatabase (ID INTEGER PRIMARY KEY AUTOINCREMENT,EMAIL TEXT, PASSWORD TEXT)")

def main():
    # Ask user what to do
    while (True):
        print("please input command what you want to do")
        print("in/out/del/pre/quit")
        user_cmd = input("Please input command: ")
        if (user_cmd == "in"):      # Input
            passwordinput()
            print("Operation successful")
        elif (user_cmd == "out"):       # Output
            passwordoutput(cursor, connection)
            print("Operation successful")
        elif (user_cmd == "del"):        # Delete
            password_delete(cursor, connection)
            print("Operation successful")
        elif (user_cmd == "pre"):       # Preview
            passwordpreview()
            print("Operation successful")
        elif (user_cmd == "quit"):      # Quit
            break
            connection.close()
        else:
            print("Unknown command, please input again")
           
# Ensure the master key is exactly 32 bytes long
def masterkey_hash(user_masterkey):
    masterkey_32bytes = user_masterkey.encode()
    if len(masterkey_32bytes) != 32:
        # If the master key is not 32 bytes long, hashed to be 32 bytes long
        hashed_masterkey = sha256(masterkey_32bytes).digest()[:32]
    else:
        hashed_masterkey = masterkey_32bytes
    return hashed_masterkey
    
# Insert queries into encryption and into the database
def passwordinput(): 
    # Ask for input (password) and masterkey
    user_masterkey = input("Masterkey: ")
    
    # ensure input is email format
    user_email = input("Email: ")
    user_password = input("Password: ")
    
    # Put masterkey and input into encryption
    box = nacl.secret.SecretBox(masterkey_hash(user_masterkey))
    encrypted_password = box.encrypt(user_password.encode())
    encrypted_email = box.encrypt(user_email.encode())
        
    # Insert output into the DB, SQL preferebly
    cursor.execute("INSERT INTO passworddatabase (EMAIL, PASSWORD) VALUES (?,?)", 
                   (encrypted_email, encrypted_password))
    connection.commit()
    print("Your query has been successfully inserted")
    
# Take enc'ed data from DB
def passwordoutput(cursor, connection):
    cursor.execute("SELECT EMAIL, PASSWORD FROM passworddatabase")
    ciphertexts = cursor.fetchall()

    # Initialize secretbox with the masterkey
    user_masterkey = input("Masterkey: ")
    box = nacl.secret.SecretBox(masterkey_hash(user_masterkey))

    # Only outputs(prints) if succesfully decrypted
    for email_ciphertext, password_ciphertext in ciphertexts:
        try:
            decrypted_email = box.decrypt(email_ciphertext)
            decrypted_password = box.decrypt(password_ciphertext)
            print("Email:", decrypted_email.decode('utf-8'), ",Password:", decrypted_password.decode('utf-8'))
        except Exception:
            pass

# Delete password from DB (passworddel())
def password_delete(cursor, connection):
    user_masterkey = input("Please input your masterkey: ")
    # Initialize secretbox with the masterkey
    box = nacl.secret.SecretBox(masterkey_hash(user_masterkey))
    
    cursor.execute("SELECT ID, EMAIL, PASSWORD FROM passworddatabase")
    ciphertexts = cursor.fetchall()
    
    # TODO correspond user input with ID to delete
    for ID, email_ciphertext, password_ciphertext in ciphertexts:
        try:
            decrypted_email = box.decrypt(email_ciphertext)
            decrypted_password = box.decrypt(password_ciphertext)
            print("Id: ", ID, "Email:", decrypted_email.decode('utf-8'), ",Password:", decrypted_password.decode('utf-8'))
        except Exception:
            pass
    user_delete = input("Please select ID to delete: ")
    
    try:
        cursor.execute("DELETE FROM passworddatabase WHERE ID=?", (user_delete,))
        connection.commit()
        print("Operation successful")
    except Exception as e:
        print("An error occurred:", e)

# Preview encrypted password without adding it to the db
def passwordpreview():
    user_masterkey = input("Masterkey: ")
    user_email = input("Email: ")
    user_password = input("Password: ")

    # Put masterkey and input into encryption
    box = nacl.secret.SecretBox(masterkey_hash(user_masterkey))
    
    encrypted_email = box.encrypt(user_email.encode())
    encrypted_password = box.encrypt(user_password.encode())
    print("Email: ", encrypted_email) 
    print("Password: ", encrypted_password)
    
if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()