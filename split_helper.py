import hashlib
import os
import sys
from mongo_utils import insert_into_mongo, find_mongo
import erasure
import glob
import blake3
import crypto

from crypto import Cipher

from crypto.Cipher import Blowfish
from crypto import Random
from struct import pack
import re
import string
import config

#directory_list = config["data_storage"]

bs = Blowfish.block_size
n = 4
f1 = "C:\Windows\Temp\ZMyfile1.txt"
f2 = "C:\Windows\Temp\\"
#iv = Random.new().read(bs)

def encrypt(data,key):
    #This function encrypts the data using symmetric algorithm
    data = str(data)
    #printable = set(string.printable)
    #data = join(list(filter(lambda x:x in printable, data)))
    key = str(key)
    data = data.encode("latin-1")
    key = key.encode("latin-1")
    
    cipher = Blowfish.new(key,Blowfish.MODE_ECB)
    plen = bs - divmod(len(data),bs)[1]
    padding = [plen]*plen
    padding = pack('b'*plen,*padding)
    encrypted_text = cipher.encrypt(data + padding)
   
    return encrypted_text.decode("latin-1")

def decrypt(data,key):
    #This function decrypts the data using symmetric algorithm"""
    print("Data: " , data)
   
    #decrypted_text = re.sub(r'[^\x20-\x7e]', '', decrypted_text)
    decrypted_text = ""
    key = 0
    for i in str(key)[:4]:
        key += ord(i)
    '''
    for i in data:
        decrypted_text += chr(ord(i) - key)   
    '''
    return str(decrypted_text)

def hash_data(data):
    result = str(blake3.blake3(data.encode()).digest().hex())
    # result = hashlib.sha1(data.encode())
    return result

def key_gen(data):
    #This function generates the key that will be used to decrypt/encrypt next data chunk
    key_text = data
    return str(hash_data(key_text))[:8]

def string_xor(string1,string2):
    num1 = ""
    for i in string1:
        num1 += str(ord(i))
    num2 = ""
    for i in string2:
        num2 += str(ord(i))
    return int(num1) ^ int(num2)

def check_file_string(filename):
    pass

def create_merkle_root(chunks):
    # This function will calculate the merkle root of the file
    # and this will be used to compare with the merkle root saved in
    # DB to check whether the file has been modified.

    # print(chunks)
    if len(chunks) == 1:
        root = chunks[0]
        return root
    chunk_hash = []
    for i in range(0,int(len(chunks)/2)):
        chunk_hash.append(str(hash_data(chunks[2*i] + chunks[2*i+1])))
    return create_merkle_root(chunk_hash)

def split_into_chunks(filename, n_chunks):
    """
    This function reads from the given file and
    divides them into chunks. It also provides padding if required.
    """
    f = open(filename, "r")
    file_data = f.read()
    length_of_file = len(file_data)
    print("The total characters in the file is : ",length_of_file)
    data_list = [] #The list will contain the chunks of data
    size_of_chunk = int(length_of_file/n_chunks) + 1
    print("Size of each chunk : ", size_of_chunk)
    for i in range(n_chunks):
        data_list.append(file_data[i * size_of_chunk : (i+1) * size_of_chunk])
    if len(data_list[-1]) <size_of_chunk : #To have all chunks of equal length.
        data_list[-1] += "#" * (size_of_chunk - len(data_list[-1]))
    f.close()
    return data_list

def proof_of_storage():
    pass

def proof_of_auth(filename, merkle_root):
    """
    This function will authenticate the data using the merkel root
    saved in the mongoDB
    """
    root = find_mongo(filename)
    if root == None:
        print("No file found with that name.")
        return False
    if merkle_root == root:
        return True
    else:
        return False

def create_filename(file_string, pwd , n):
    #This is will create filename of the chunks which will be unique
    
    file_list = []
    x = string_xor(file_string,pwd)
    for i in range(n):
        x += i
        file_hash = str(hash_data(str(x))) + ".txt"
        file_list.append(file_hash)
    return file_list

def read_and_write_file(filename, mode):
    # filename = "parity/" + filename
    f = open(filename, mode)
    return f

def create_parity_files(filename, p1,p2):
    """
    This function calls the erasure coding module
    to create parity chunks
    """
    filename_p1 = hash_data(filename + "parity1") + ".txt"
    filename_p2 = hash_data(filename + "parity2") + ".txt"
    f = read_and_write_file(filename_p1, "w")
    f.write(str(p1))
    f.close()
    f = read_and_write_file(filename_p2, "w")
    f.write(str(p2))
    f.close()

def read_parity(filename):
    filename_p1 = hash_data(filename + "parity1") + ".txt"
    filename_p2 = hash_data(filename + "parity2") + ".txt"
    f = open(filename_p1, "r")
    p1 = int(f.read())
    f.close()
    f = open(filename_p2, "r")
    p2 = int(f.read())
    f.close()
    return p1,p2

def write_file(file_name,pwd,n,file_chunks):
    """
    This function will write into the file the encrypted version of the
    data and call another function to create parity chunks
    """
    print("\nIn write_file .......")
    if file_name == "":
        exit(1)
    hash_of_data = []
    enc_data = []
    filename = file_name
    file_name = file_name
    key = pwd
    
    file_list = create_filename(file_name,pwd,4)
    #print("File Name: ",file_list)
    cnt=0
    
    for data in file_chunks:
        print("Chunk: ", data)
        # enc_data.append(erasure.encode(data))
        key = key_gen(data)
        hash_of_data.append(key)
        file_=file_list[cnt]
        cnt=cnt+1
        #for file_ in file_list:
        print("File:  ", file_)
        f = open(file = file_, mode = "w", encoding = "latin-1")
        enc_d = encrypt(data,key)
        print("Encode Data: ",enc_d)
        f.write(enc_d)
        enc_data.append(erasure.encode(enc_d))
        #enc_data.append(enc_d)
        f.close()
        
        file1_=f2+file_
        f4 = open(file = file1_, mode = "w", encoding = "latin-1")
        f4.write(enc_d)
        f4.close()

        key = key_gen(data)
        file_name = file_list[0]
        merkle_root = create_merkle_root(hash_of_data)
        #print("Merkle Root after Encryption : ",merkle_root)

        #Creating Parity Bits
        # print("Encoded version : ", enc_data)
        p1,p2 = erasure.create_parity_block(enc_data)
        # print("Parity Bits : ", p1,p2)
        create_parity_files(filename,p1,p2)
        insert_into_mongo(filename, merkle_root)
    return merkle_root

def retrieve_chunk(filename, pwd):
    #This function will retrieve chunks given the filename
    
    if filename == "":
        exit(1)
    root_filename = string_xor(filename, pwd)

    found = False
    root_chunk = None
    for i in range(1): #Max redundancy is 4
        root = root_filename
        root += i
        root_chunk = str(hash_data(str(root))) + ".txt"
        root_chunk = filename # (AB)
        #print("Root Chunk:   ", root_chunk)

        found = find_file(root_chunk)
        if found == True:
            return True, root_chunk
        if found == False:
            print("Error: A file could not be found. Somebody has tampered with your file system.")
            return False, root_chunk
            # exit(1)
    return False, root_chunk

def retrieve_all_chunks(filename, pwd):
    """
    This is the main function which will retrieve all chunks and
    check whether chunks are missing or not
    """
    all_chunks = []
    no_of_chunks = 4
    ###
    file_list = list(glob.glob("*.txt"))
    for a in range(4):
        print("File Name: ", file_list[a])
        file_chunk = file_list[a]
        valid,file_ = retrieve_chunk(file_chunk,pwd)
        if valid == False:
            print("Chunk Missing\n")
            all_chunks.append("")
            return False, all_chunks
        elif valid == True:
            all_chunks.append(file_)
        else:
            print("Could not retrieve the file. File Chunk Missing.")
            exit(1)
        file_chunk = file_
    ###
    #missing = all_chunks.count("")
    #print(all_chunks)
    return True, all_chunks

def read_chunk(filename,chunks):
    """
    This function will read chunks and decrypt them
    using the algorithm
    """
    data = []
    bk=0
    for i in chunks:
        if i != "":
            f = open(file = i, mode = "r", encoding = "latin-1")
            red=f.read()
            
            fa=f2+i
            fb = open(file = fa, mode = "r", encoding = "latin-1")
            red1=fb.read()

            if (red!=red1):
                print("File content tampered...")
                bk=1
                break

            data.append(red)
            f.close()
            #os.remove(i)
        else:
            print("No data")
            data.append("")
    print("Data (read_chunk): ", data)
    if (bk>0):
        return False, data
    else:
        return True, data

def read_chunk1():
    f = open(file =f1, mode = "r", encoding = "latin-1")
    print(f.read())
    f.close()
    return True

def write_chunk1(filename):
    f_1 = open(file =filename, mode = "r", encoding = "latin-1")
    f_2 = open(file =f1, mode = "w", encoding = "latin-1")
    f_2.write(f_1.read())
    f_1.close()
    f_2.close()
    return True

def join_chunks(filename,chunks_list,pwd):
    """
    This will join the chunks and create fresh merkle root
    and compare it with the one stored in mongoDB
    """
    original_text = ""
    chunks_of_data = []
    key = pwd
    print("\n")
    #finding missing values
    for i in chunks_list:
        if len(i)<50:
            data = decrypt(i,key)
            #chunks_of_data.append(hash_data(data))
            #original_text += data
            #key = key_gen(data)

    return True

def find_file(filename):
    # This helper function checks whether the file exists or not
    
    file_list2 = list(glob.glob("C:\Windows\Temp\*.txt"))  # List all *.txt files from the directory
    l=len(file_list2)
    for x in range(l):
        file_list3=file_list2[x]
        file_list3=file_list3.replace("C:\Windows\Temp\\","")
        if (file_list3 == filename):
            return True
    #if (filename in file_list2):
    #    return True
    #else:
    return False
