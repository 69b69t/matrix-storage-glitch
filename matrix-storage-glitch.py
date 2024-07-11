import sys
import requests
import base64
import numpy as np

from time import sleep

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

homeserver = "matrix.org"

max_upload_endpoint = "https://"+homeserver+"/_matrix/media/v3/config"
upload_url = "https://"+homeserver+"/_matrix/media/v3/upload"
download_url = "https://"+homeserver+"/_matrix/media/v3/download/"
headers = {"Authorization": "ENTER TOKEN HERE. SHOULD LOOK LIKE Bearer fsglkijnrgljnweasdfaewf"}

#helper functions

def save_to_file(file_path, content_blocks):
    #save array to text file
    np.savetxt(file_path, content_blocks, delimiter=",", fmt="%s")

def read_from_file(file_path):
    #read text file and return array
    return np.loadtxt(file_path, delimiter=",", dtype=str).tolist()

def get_max_upload():
    #hit up the max upload endpoint
    response = requests.get(max_upload_endpoint, headers=headers)
    if(response.status_code != 200):
        print("ERROR GETTING MAX MEDIA SIZE. STOP")
        sys.exit(-1)
    return int(response.json()["m.upload.size"])

def extract_homeserver(mxc_uri):
    #remove the "mxc://" prefix
    without_prefix = mxc_uri.replace("mxc://", "")
    
    #split the remaining string by "/"
    parts = without_prefix.split("/")
    
    #the homeserver is the first part
    homeserver = parts[0]
    
    return homeserver

def upload_data(data):
    #uploads a chunk of data to a homeserver
    
    while True:
        #post data chunk
        response = requests.post(upload_url, data=data, headers=headers)

        #if response is 200, good. return content_uri
        if(response.status_code == 200):
            content_uri = response.json()["content_uri"]
            return content_uri
        #if 429, we were rate limited. wait the necessary time and try again
        elif(response.status_code == 429):
            #rate limited. sleep for response ms
            print("rate limited for " + str(response.json()[retry_after_ms]) + " ms")
            time.sleep(float(response.json()[retry_after_ms])/1000)
        #otherwise, error out
        else:
            print("ERROR SENDING TO HOMESERVER" + str(response.status_code))

def download_data(content_uri):
    slash_index = content_uri.rfind('/')
    characters_after_slash = content_uri[slash_index + 1:]
    
    while True:
        #get data chunk
        response = requests.get(download_url + extract_homeserver(content_uri) + "/" + characters_after_slash + '?allow_redirect=true', headers=headers)
        
        #if response is 200, good. return content
        if(response.status_code == 200):
            return response.content
        #if 429, we were rate limited. wait the necessary time and try again
        elif(response.status_code == 429):
            #rate limited. sleep for response ms
            print("rate limited for " + str(response.json()[retry_after_ms]) + " ms")
            time.sleep(float(response.json()[retry_after_ms])/1000)
        #otherwise, error out
        else:
            print("ERROR GETTING FROM HOMESERVER" + str(response.status_code))

def encrypt_and_upload(file_path):
    content_blocks = []

    max_upload = get_max_upload()

    with open(file_path, 'rb') as file:
        while True:
            #get new data
            data = file.read(max_upload)

            #if end of file, break
            if data == b'':
                break
            
            #get new key, hmac_key and init a AES cipher and HMAC with the new keys
            key = get_random_bytes(32)
            hmac_key = get_random_bytes(32)
            cipher = AES.new(key, AES.MODE_CTR)
            hmac_object = HMAC.new(hmac_key, digestmod=SHA256)

            #bundle hmac(plaintext, hmac_key) as well
            #calculate ciphertext and hmac
            ciphertext = cipher.encrypt(data)
            hmac = hmac_object.update(data).digest()

            #write base64 data to content_blocks
            key_b64 = base64.b64encode(key).decode('utf-8')
            nonce_b64 = base64.b64encode(cipher.nonce).decode('utf-8')
            hmac_key_b64 = base64.b64encode(hmac_key).decode('utf-8')
            hmac_b64 = base64.b64encode(hmac).decode('utf-8')

            #upload ciphertext and get 
            content_uri = upload_data(ciphertext)
            print(content_uri + " uploaded")

            #append the necessary info to the array
            content_blocks.append([content_uri, key_b64, nonce_b64, hmac_key_b64, hmac_b64])
    return content_blocks

def download_and_decrypt(file_path, content_blocks):
    with open(file_path, 'wb') as file:
        for content_block in content_blocks:
            #retrieve data
            content_uri = content_block[0]
            key = base64.b64decode(content_block[1])
            nonce = base64.b64decode(content_block[2])
            hmac_key = base64.b64decode(content_block[3])
            expected_hmac = base64.b64decode(content_block[4])

            #make cipher and hmac objects
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            hmac_object = HMAC.new(hmac_key, digestmod=SHA256)

            #download ciphertext and decrypt
            ciphertext = download_data(content_uri)
            data = cipher.decrypt(ciphertext)

            #calculate hmac and check against our known hmac
            #on failure print a warning message
            
            print(content_uri + " downloaded")
            #print(base64.b64encode(key).decode('utf-8'))
            #print(base64.b64encode(nonce).decode('utf-8'))
            #print(base64.b64encode(hmac_key).decode('utf-8'))
            #print(base64.b64encode(expected_hmac).decode('utf-8'))

            computed_hmac = hmac_object.update(data).digest()
            #print(base64.b64encode(computed_hmac).decode('utf-8'))

            #hmac check has passed, append data to file
            file.write(data)





def main():
    content_blocks = encrypt_and_upload('/enter/path/to/upload')

    save_to_file('/enter/path/to/save/to', content_blocks)

    content_blocks = read_from_file("/enter/path/to/load/from")
    download_and_decrypt("/enter/path/to/download/from", content_blocks)

if __name__ == "__main__":
    main()
