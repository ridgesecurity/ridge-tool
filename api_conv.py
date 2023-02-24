import random
import string
import requests
import re
import argparse
import webbrowser
import json

import os
os.environ['REQUESTS_CA_BUNDLE'] = 'ca.cert'

def is_json(myjson):
  try:
    json.loads(myjson)
  except ValueError as e:
    return False
  return True

def sent_to_api(web_page, proxy, header, data):
    status = 0
    if header == 'None':
        try:
            response_post = requests.post(web_page, proxies=proxy, data=data)
            status = response_post.status_code
            if str(status).startswith('5'):
                print('HTTP/1.1 ', status, 'Internal Error')
        except requests.exceptions.RequestException as e:
            print('Error', e)
        try:
            response_get = requests.get(web_page, proxies=proxy, data=data)
            status = response_get.status_code
            if str(status).startswith('5'):
                print('HTTP/1.1 ', status, 'Internal Error')
        except requests.exceptions.RequestException as e:
            print('Error', e)
        try:
            response_put = requests.put(web_page, proxies=proxy, data=data)
            status = response_put.status_code
            if str(status).startswith('5'):
                print('HTTP/1.1 ', status, 'Internal Error')
        except requests.exceptions.RequestException as e:
            print('Error', e)
    else:
        try:
            response_post = requests.post(web_page, proxies=proxy, headers=header, data=data)
            status = response_post.status_code
            if str(status).startswith('5'):
                print('HTTP/1.1 ', status, 'Internal Error')
        except requests.exceptions.RequestException as e:
            print('Error', e)
        try:
            response_get = requests.get(web_page, proxies=proxy, headers=header, data=data)
            status = response_get.status_code
            if str(status).startswith('5'):
                print('HTTP/1.1 ', status, 'Internal Error')
        except requests.exceptions.RequestException as e:
            print('Error', e)
        try:
            response_put = requests.put(web_page, proxies=proxy, headers=header, data=data)
            status = response_put.status_code
            if str(status).startswith('5'):
                print('HTTP/1.1 ', status, 'Internal Error')
        except requests.exceptions.RequestException as e:
            print('Error', e)
    if not str(status).startswith('5'):
        output = []
        #post
        if is_json(response_post.content):
            post_data = response_post.json()
        else:
            post_data = response_post.content
        output.append(post_data)
        print(post_data)
        #get
        if is_json(response_get.content):
            get_data = response_get.json()
        else:
            get_data = response_get.content
        output.append(get_data)
        print(get_data)
        #put
        if is_json(response_put.content):
            put_data = response_put.json()
        else:
            put_data = response_put.content
        output.append(put_data)
        print(put_data)
        '''
        for key in post_data:
            if key == 'url':
                webbrowser.open(post_data[key], new=2)
        '''
        #print(web_page, header, data)
        return output

def convolute_api(text, proxy, fuzz_times = 0, auth_token = 'keep', fuzzy = False):
    f = open(text, "r")
    all_of_it = f.read()
    f.close()
    proxies = {
        "https" : proxy,
    }
    to_fuzz_dic = [
        'reference', 'transaction_id', 'q', 'trans_reference', 'Authorization', 
        'reference', 'openid', 'store_code', 'token', 'barcode', 'pos_local_time',
    ]
    #split input for 'curl' commands
    api_arr = all_of_it.split('curl')
    for y in range(len(api_arr)):
        temp = []
        #split by data
        d = "-d"
        data_arr =  [d+e for e in api_arr[y].split(d) if e]
        #single_arr = api_arr[y].split("\n")
        if len(data_arr) > 1:
            #find webpage
            web_page = re.findall(r'(https?://[^\s]+)', data_arr[0])[0]
            #if web_page[0:5] == 'https': 
            #    web_page = 'http' + web_page[5:]
            headers_dic = {}
            data_dic = {}
            #data = ''
            #create Auth Token (currently supports Bearer)
            #if we want random
            if auth_token == 'random':
                headers_dic['Authorization'] = 'Bearer ' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))
            elif auth_token == 'keep':
                #check for header
                if len(data_arr[0].split('-H')) > 1:
                    #look for Bearer auth token
                    prev_token = re.findall(r'Bearer\s[a-zA-Z0-9]+', data_arr[0])[0]
                    headers_dic['Authorization'] = 'Bearer ' + prev_token.split()[1]
                else:
                    pass
            else:
                #for custom token
                headers_dic['Authorization'] = auth_token
            #loop thorugh the data
            for x in range(len(data_arr)-1):
                x = x+1
                #text search each line
                in_type = data_arr[x][0:2]
                #for data
                if in_type == '-d':
                    data_split = data_arr[x].split("=")
                    data_name = data_split[0][3:]
                    if len(data_split) > 2:
                        for i in range(len(data_split)-2):
                            data_split[1] += '=' + data_split[i+2]
                    #['-d payment_method', '"alipay" \\ ']
                    # -d pos_local_time="2017-01-27 01:39:42"                
                    textRegex = re.compile(r'https?://[^\s]+|\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}|[a-zA-Z0-9]+_[a-zA-Z0-9]+|[a-zA-Z0-9]+')
                    data_value = textRegex.findall(data_split[1])
                    if data_value[0][-1] == '"':
                        data_value[0] = data_value[0][:-1]
                    data_dic[data_name] = data_value[0]
            #if header empty
            if len(headers_dic) == 0:
                print('\nTesting: ', web_page)
                api_response = sent_to_api(web_page, proxies, 'None', data_dic)
            else:
                print('\nTesting: ', web_page)
                api_response = sent_to_api(web_page, proxies, headers_dic, data_dic)
            #for each header we want to fuzz
            for i in range(fuzz_times):
                for key in headers_dic:
                    if key in to_fuzz_dic:
                        if key == 'Authorization':
                            headers_fuzz_dic = headers_dic.copy()
                            headers_fuzz_dic['Authorization'] = 'Bearer ' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))
                            print('fuzzing: ', key)
                            api_response = sent_to_api(web_page, proxies, headers_fuzz_dic, data_dic)
            #for each data we want to fuzz
            for i in range(fuzz_times):
                for key in data_dic:
                    if key in to_fuzz_dic:
                        data_value = data_dic[key]
                        if data_value[0:4] == 'http':
                            #ignore http
                            pass
                        else:
                            temp = ''
                            for j in range(len(data_value)):
                                if data_value[j].isalpha():
                                    temp += random.choice(string.ascii_lowercase)
                                elif data_value[j].isnumeric():
                                    temp += random.choice(string.digits)
                                else:
                                    temp += data_value[j]
                            data_fuzz_dic = data_dic.copy()
                            data_fuzz_dic[key] = temp
                            print('fuzzing: ', key)
                            api_response = sent_to_api(web_page, proxies, headers_dic, data_fuzz_dic)



class CommandLine:
    def __init__(self):
        parser = argparse.ArgumentParser(description = "Parser to read inputs for api_conv")
        parser.add_argument('text', help = 'text file to read of curl api calls')
        parser.add_argument("-a", "--auth_token", help = "Authorization token, can be 'random', 'keep' or custom token", required = False, default = 'keep')
        parser.add_argument("-p", "--proxy", help = "Proxy Server to run on", required = True)
        parser.add_argument("-f", "--fuzz_times", help = "Number of times to fuzz", required = False, default = 0)
        
        argument = parser.parse_args()
        convolute_api(argument.text, argument.proxy, int(argument.fuzz_times), argument.auth_token)


if __name__ == '__main__':
    app = CommandLine()