## Swagger OpenApi 3.0
## Please strictly follow Swagger documentation 
## Authorization token must be provided in authentication files

import yaml
import requests
import json
import argparse
import random

import os
os.environ['REQUESTS_CA_BUNDLE'] = 'ca.cert'

# ignore warnings for now
requests.packages.urllib3.disable_warnings() 


def convolute_api(swfile, proxy=None, authfile = None, fuzz = False, fuzz_path = '/text.txt'):

    if '.yaml' in swfile:
        with open(swfile, 'r') as file:
            yaml_data = yaml.safe_load(file)
    elif '.json' in swfile:
        with open(swfile) as file:
            yaml_data = json.load(file)
    else:
        raise ValueError("Only swagger.yaml or swagger.json are allowed")
    
    proxies = {
        "https" : proxy,
        "http": proxy,
    }

    # read all authenticaiton 
    if authfile:
        with open(authfile) as json_file:
            auth_data = json.load(json_file)
    else:
        auth_data = {}

    # get base url
    base_url = yaml_data['servers'][0]['url']

    # find all calls that need authentication
    auth_api_calls = find_authenticated_api_calls(yaml_data)

    # excute calls with authentication first
    auth_excuted = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
        "Accept-Encoding": "*",
        "Connection": "keep-alive"
    }

    fuzz_list = None
    if fuzz:
        fuzz_list = read_fuzz_list_from_file(fuzz_path)


    if auth_api_calls:
        for calls in auth_api_calls:
            path = calls['path']
            method = calls['method']
            print(path + ' '+ method)

            send_request(path, method, base_url, yaml_data, proxies, auth_data, headers, fuzz, fuzz_list)

            
            auth_excuted.append([path,method])


    for path, path_data in yaml_data['paths'].items():
        for method in path_data.keys():
            # if [path,method] in auth_excuted:
            #     # ignore the calls that have been excuted
            #     continue
            # else:
            print(path + ' '+ method)
            send_request(path, method, base_url, yaml_data, proxies, auth_data, headers, fuzz, fuzz_list)

            print('------')


"""
helper functions
"""
def find_authenticated_api_calls(yaml_data):
    authenticated_api_calls = []

    if 'paths' in yaml_data:
        for path, path_yaml_data in yaml_data['paths'].items():
            for method, method_yaml_data in path_yaml_data.items():
                if method_yaml_data.get('security'):
                    authenticated_api_calls.append({
                        'path': path,
                        'method': method
                    })
    # list of dict
    return authenticated_api_calls


def is_json(myjson):
    try:
        json.loads(myjson)
    except ValueError as e:
        return False
    return True


def fuzzer(datatype):
    # TODO: add more fuzzer function
    fuzz_dic = {'integer':10, 'string':'abc','array':['defalut array'],
                'boolean':True,'object':{'id':1},'number':3.14,
                'file':'ridge_auth.json'}
    val = fuzz_dic[datatype]
    return val


def get_referenced_schema(yaml_data, ref):
    # Split the reference string to get the component and schema names
    _, _, _, schema = ref.split('/')
    # Retrieve the referenced schema from the components/schemas section
    referenced_schema = yaml_data['components']['schemas'][schema]

    return referenced_schema


def generate_data_from_schema(yaml_data,schema):
    json_data = {}
    
    for property_name, property_data in schema.get('properties', {}).items():
        if 'default' in property_data:
                json_data[property_name] = property_data.get('default')
        elif 'example' in property_data:
            json_data[property_name] = property_data.get('example')
        elif 'enum' in property_data:
            json_data[property_name] = random.choice(property_data.get('enum'))
        elif '$ref' in property_data:
            ref =  property_data.get('$ref')
            ref_schema = get_referenced_schema(yaml_data,ref)
            ref_data = generate_data_from_schema(yaml_data,ref_schema)
            json_data[property_name] = ref_data
        else:
            data_type = property_data.get('type')
            if data_type == 'array':
                if '$ref' in property_data['items']:
                    ref = property_data['items']['$ref']
                    body_schema = get_referenced_schema(yaml_data,ref)
                    json_data[property_name] = [generate_data_from_schema(yaml_data,body_schema)]
                else:
                    json_data[property_name] = [fuzzer(property_data['items']['type'])]
            else:
                json_data[property_name] = fuzzer(data_type)

    return json_data


def add_to_header(header, auth_details):
    if auth_details['type'] == 'http':
        add_header = auth_details['scheme'] + " " + auth_details['value']
        header['Authorization'] = add_header
    elif auth_details['type'] == 'oauth2':
        add_header = 'Bearer' + auth_details['value']
        header['Authorization'] = add_header
    elif auth_details['type'] == 'apiKey':
        if 'in' in auth_details and auth_details['in'] == 'cookie':
                header['Cookie'] = auth_details['name'] +'=' + auth_details['value']
        else:
            header[auth_details['name']] = auth_details['value']
    return header


def extract_header(headers,responses):
    # api_key
    response_api_key = responses.headers.get('X-API-KEY')
    response_auth = responses.headers.get('Authorization')
    if not response_api_key:
        if is_json(responses.content):
            response_data = responses.json()
            if isinstance(response_data, dict):
                if response_data.get('api_key'):
                    response_api_key = response_data.get('api_key')
                if response_data.get('auth_token'):
                    response_auth = "bearer "+response_data.get('auth_token')
    if response_api_key:
        headers.update({'X-API-KEY': response_api_key})
    if response_auth:
        headers.update({'Authorization': response_auth})
    # cookie
    cookie = responses.headers.get('Set-Cookie')
    if cookie:
        headers.update({'Cookie': cookie})

    return headers
    

def read_fuzz_list_from_file(file_path):
    with open(file_path, 'r') as file:
        fuzz_list = file.read().splitlines()
    # list of strings
    print(fuzz_list)
    return fuzz_list


def convert_data_type(value, type_string):
    try:
        if type_string == 'integer':
            return int(value)
        elif type_string == 'string':
            return str(value)
        elif type_string == 'array':
            return list(value)
        elif type_string == 'boolean':
            return bool(value)
        elif type_string == 'object':
            # Assuming value is a JSON-like string for simplicity
            return json.loads(value)
        elif type_string == 'number':
            return float(value)
        else:
            return None  # Return None for unsupported types
    except ValueError:
        return None  # Return None if conversion fails


"""
request code
"""

## NEW: add headers
def send_request(path, method, base_url, yaml_data, proxy, auth_data, headers, fuzz=False, fuzz_list=None):
    if fuzz:
        for fuzz_value in fuzz_list:
            # construct post_data and headers based on fuzz_value
            endpoint_url, post_data, headers = construct_data(path, method, base_url, yaml_data, auth_data, headers, fuzz_value)
            make_request(method, endpoint_url, proxy, headers, post_data, verify=False)
    else:
        # construct post_data and headers without fuzzing
        endpoint_url, post_data, headers = construct_data(path, method, base_url, yaml_data, auth_data, headers)
        make_request(method, endpoint_url, proxy, headers, post_data, verify=False)





def construct_data(path, method, base_url, yaml_data, auth_data, headers, fuzz_value=None):
    # construct post_data and headers logic based on method_data and fuzz_value
    post_data = {}
    method_data = yaml_data['paths'][path][method]

    path_query = ''
    if 'parameters' in yaml_data:
        for parameter in yaml_data['parameters']:
            para_name = parameter['name']
            if 'default' in parameter:
                insertval = parameter.get('default')
            elif 'example' in parameter:
                insertval = parameter.get('example')
            elif 'enum' in parameter['schema']:
                insertval = random.choice(parameter['schema'].get('enum'))
            elif parameter['schema']['type'] == 'array':
                if '$ref' in parameter['schema']['items']:
                    ref = parameter['schema']['items']['$ref']
                    body_schema = get_referenced_schema(yaml_data,ref)
                    insertval = [generate_data_from_schema(yaml_data,body_schema)]
                else:
                    if not fuzz_value:
                        insertval = [fuzzer(parameter['schema']['items']['type'])]
                    else:
                        insertval = [convert_data_type(fuzz_value,parameter['schema']['items']['type'])]
            else:
                if not fuzz_value:
                    insertval = fuzzer(parameter['schema']['type'])
                else:
                    insertval = convert_data_type(fuzz_value,parameter['schema']['type'])
            
            # add the parameter based on the 'in' position
            if parameter['in'] == 'query':
                query_param = ''
                if insertval != '':
                    if type(insertval) == list:
                        for contents in insertval:
                            query_param = f"{query_param}&{para_name}={contents}" 
                    else:
                        query_param = f"{para_name}={insertval}"
                    if path_query == '':
                        path_query = f"?{query_param}"
                    else:
                        path_query = f"{path_query}&{query_param}"
            elif parameter['in'] == 'path':
                placeholder = '{' + para_name + '}'
                path = path.replace(placeholder, str(insertval))
            elif parameter['in'] == 'header' or  parameter['in'] =='cookie':
                if para_name in auth_data.keys():
                    headers = add_to_header(headers,auth_data[para_name])
                else:
                    headers[para_name] = insertval
        
    endpoint_url = base_url+path+path_query

    # generate request body
    if method in ['post', 'put']:
        if 'requestBody' in method_data:
            request_body = method_data['requestBody']
            request_data = request_body['content']
            for _, form_details in request_data.items():
                if 'example' in form_details['schema']:
                    post_data = form_details['schema']['example']
                    break
                elif '$ref' in form_details['schema']:
                    ref = form_details['schema']['$ref']
                    body_schema = get_referenced_schema(yaml_data,ref)
                    post_data = generate_data_from_schema(yaml_data,body_schema)
                elif form_details['schema']['type'] == 'object':
                    post_data = generate_data_from_schema(yaml_data,form_details['schema'])
                elif form_details['schema']['type'] == 'array':
                    if '$ref' in form_details['schema']['items']:
                        ref = form_details['schema']['items']['$ref']
                        body_schema = get_referenced_schema(yaml_data,ref)
                        post_data = [generate_data_from_schema(yaml_data,body_schema)]
                    else:
                        if not fuzz_value:
                            post_data = [fuzzer(form_details['schema']['type'])]
                        else:
                            post_data = [convert_data_type(fuzz_value,form_details['schema']['type'])]
                else:
                    if not fuzz_value:
                        post_data  = fuzzer(form_details['schema']['type'])
                    else:
                        post_data = convert_data_type(fuzz_value,form_details['schema']['type'])

    return endpoint_url, post_data, headers


def make_request(method, endpoint_url, proxy, headers, post_data, verify=False):
    status = 0
    try:
        if method in ['get', 'delete', 'options']:
            response = requests.request(method, endpoint_url, proxies=proxy, headers=headers, verify=verify)
        elif method in ['post', 'put']:
            response = requests.request(method, endpoint_url, proxies=proxy, headers=headers, json=post_data, verify=verify)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        status = response.status_code
        if str(status).startswith('5'):
            print(f'HTTP/1.1 {status} Internal Error')

        if isinstance(response, requests.Response):
            print(f"URL: {endpoint_url}")
            print("Headers:", headers)
            print("Body:", post_data)
            print("Response Code:", response.status_code)
            headers = extract_header(headers, response)
        else:
            print(response)

    except requests.exceptions.RequestException as e:
        print(f'Error: {e}')

    

class CommandLine:
    def __init__(self):
        parser = argparse.ArgumentParser(description = "Parser to read inputs for swagger_conv")
        parser = argparse.ArgumentParser(description="Parser to read inputs for swagger_conv")
        parser.add_argument("swagger_file", help='Swagger file to read, yaml or json')
        parser.add_argument("-a", "--auth_json", help="Authorization data", required=False, default=None)
        parser.add_argument("-p", "--proxy", help="Proxy Server to run on", required=False)
        parser.add_argument("-f", "--fuzz", help="Start default", action="store_true")  # Change the default to False
        parser.add_argument("-fl", "--fuzz_path", help="Use self-prepared fuzz wordlist", required=False, default='examples/wordlist.txt')
        
        argument = parser.parse_args()
        convolute_api(argument.swagger_file, argument.proxy,  argument.auth_json, argument.fuzz, argument.fuzz_path)
        

if __name__ == '__main__':
    app = CommandLine()
    #  convolute_api('examples/openapi.json', None, 0, 'examples/auth.json')
    #  python3 swagger_conv.py examples/openapi.json -a examples/auth.json
    