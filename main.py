import hashlib
import requests
import sys


def request_from_api(query_char):
    url = f'https://api.pwnedpasswords.com/range/{query_char}'
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError('Error fetching data from api')
    return res


def hash_password(password):
    return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()


def get_count_from_response(response, tail):
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return count
    return 0


def check_password_pwned(password):
    hashed_password = hash_password(password)
    first5, tail = hashed_password[:5], hashed_password[5:]
    response = request_from_api(first5)
    return get_count_from_response(response, tail)


def main(passwords):
    for password in passwords:
        print(f'checking for password "{password}" ....')
        count = check_password_pwned(password)
        if count:
            print(f'The password {password} is not safe, it was found {count} times....')
        else:
            print(f'The password {password} is good to go!!!')
    return 'Done!!.'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
