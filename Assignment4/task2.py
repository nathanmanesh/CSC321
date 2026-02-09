import nltk
import bcrypt
import time
from nltk.corpus import words
from multiprocessing import Pool, Manager, cpu_count

"""
notes:

- example for user format:
    - “Bilbo:$2b$08$L.z8uq99JkFAvX/Q1jGRI.TzrHIIxWMoRi/VzO1sj/UvVFPgW8dW.”
    - User: Bilbo
    - Alogrithm: 2b or bcrypt
    - Workfactor: 8
    - Salt: L.z8uq99JkFAvX/Q1jGRI.
    - Hash value: TzrHIIxWMoRi/VzO1sj/UvVFPgW8dW.

Workfactor 8: Bilbo, Gandalf, Thorin (3 users) - ~30ms per hash
Workfactor 9: Fili, Kili (2 users) - ~60ms per hash
Workfactor 10: Balin, Dwalin, Oin (3 users) - ~110ms per hash
Workfactor 11: Gloin, Dori, Nori (3 users) - ~220ms per hash
Workfactor 12: Ori, Bifur, Bofur (3 users) - ~420ms per hash
Workfactor 13: Durin (1 user) - ~840ms per hash
 

- users with the same workfactor share the same salt


"""

# function to crack password of each chunk of dictionary (split up by WF)
def crack_chunk(args):
    word_chunk, users, found_passwords, process_id = args

    for word in word_chunk:

        # stop if all passwords are found
        if len(found_passwords) >= len(users):
            break
    
        for user in users:
            if user["username"] in found_passwords:
                continue

            if bcrypt.checkpw(word.encode(), user['full_hash'].encode()):
                found_passwords[user['username']] = word
                break
    
    return None
    

# some code generation using ChatGPT
def main():

    # download word corpus if not already
    try:
        words.words()
    except LookupError:
        nltk.download('words')

    # get dictionary of 6-10 letter words
    all_words = words.words()
    word_list = [word.lower() for word in all_words if 6 <= len(word) <= 10]

    # parse shadow file and group users by salt
    hash_groups = {}

    shadow_data = """Bilbo:$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq
                    Gandalf:$2b$08$J9FW66ZdPI2nrIMcOxFYI.q2PW6mqALUl2/uFvV9OFNPmHGNPa6YC
                    Thorin:$2b$08$J9FW66ZdPI2nrIMcOxFYI.6B7jUcPdnqJz4tIUwKBu8lNMs5NdT9q
                    Fili:$2b$09$M9xNRFBDn0pUkPKIVCSBzuwNDDNTMWlvn7lezPr8IwVUsJbys3YZm
                    Kili:$2b$09$M9xNRFBDn0pUkPKIVCSBzuPD2bsU1q8yZPlgSdQXIBILSMCbdE4Im
                    Balin:$2b$10$xGKjb94iwmlth954hEaw3O3YmtDO/mEFLIO0a0xLK1vL79LA73Gom
                    Dwalin:$2b$10$xGKjb94iwmlth954hEaw3OFxNMF64erUqDNj6TMMKVDcsETsKK5be
                    Oin:$2b$10$xGKjb94iwmlth954hEaw3OcXR2H2PRHCgo98mjS11UIrVZLKxyABK
                    Gloin:$2b$11$/8UByex2ktrWATZOBLZ0DuAXTQl4mWX1hfSjliCvFfGH7w1tX5/3q
                    Dori:$2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq
                    Nori:$2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12
                    Ori:$2b$12$rMeWZtAVcGHLEiDNeKCz8OiERmh0dh8AiNcf7ON3O3P0GWTABKh0O
                    Bifur:$2b$12$rMeWZtAVcGHLEiDNeKCz8OMoFL0k33O8Lcq33f6AznAZ/cL1LAOyK
                    Bofur:$2b$12$rMeWZtAVcGHLEiDNeKCz8Ose2KNe821.l2h5eLffzWoP01DlQb72O
                    Durin:$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"""

    for line in shadow_data.strip().split('\n'):
        username, full_hash = line.split(':')
        salt = full_hash[:29]
        
        if salt not in hash_groups:
            hash_groups[salt] = []
        
        hash_groups[salt].append({
            'username': username,
            'full_hash': full_hash
        })

    results = {}

    # crack passwords for each group
    for salt, users in hash_groups.items():
     
        start_time = time.time()
        
        num_cores = cpu_count()
        
        # split dictionary across CPU cores
        chunk_size = len(word_list) // num_cores
        chunks = []

        for i in range(num_cores):
            start_idx = i * chunk_size

            if i < num_cores - 1:
                end_idx = start_idx + chunk_size

            else:
                end_idx = len(word_list)

            chunks.append(word_list[start_idx:end_idx])


        with Manager() as manager:

            found = manager.dict()
            args = [(chunk, users, found, i) for i, chunk in enumerate(chunks)]


            with Pool(processes=num_cores) as pool:
                pool.map(crack_chunk, args)
            
            # store results with timing
            for username, password in found.items():
                elapsed = time.time() - start_time
                results[username] = {
                    'password': password,
                    'time': elapsed
                }
        

    # print final results
    print("\nCracked Passwords:")
    print("-"*60)

    for username in sorted(results.keys()):
        info = results[username]
        print(f"{username}: '{info['password']}' (cracked in {info['time']:.2f}s)")


if __name__ == "__main__":
    main()