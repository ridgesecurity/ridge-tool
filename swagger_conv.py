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


def convolute_api(swfile, proxy=None, fuzz_times = 0, authfile = None, fuzzy = False):

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
    headers = {}
    if auth_api_calls:
        for calls in auth_api_calls:
            path = calls['path']
            method = calls['method']
            print(path + ' '+ method)

            responses = send_request(path, method, base_url, yaml_data, proxies, auth_data, headers)

            if type(responses) == requests.Response:
                # print(responses.headers)
                # print(responses.content)
                print(responses.status_code)
                # extract cookie/api-key from response header and record so that it can be added to the subsequent header.
                headers = extract_header(headers,responses)
            else:
                print(responses)
            print('------')
            
            auth_excuted.append([path,method])


    for path, path_data in yaml_data['paths'].items():
        for method in path_data.keys():
            if [path,method] in auth_excuted:
                # ignore the calls that have been excuted
                continue
            else:
                print(path + ' '+ method)
                responses = send_request(path, method, base_url, yaml_data, proxies, auth_data, headers)

                if type(responses) == requests.Response:
                    # print(responses.headers)
                    # print(responses.content)
                    print(responses.status_code)
                    # extract cookie/api-key from response header and record so that it can be added to the subsequent header.
                    # headers = extract_header(headers,responses)
                else:
                    print(responses)
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
        add_header = auth_details['scheme'] + auth_details['value']
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
    if not response_api_key:
        if is_json(responses.content):
            response_data = responses.json()
            try:
                response_api_key = response_data.get('api_key')
            except AttributeError:
                pass
    if response_api_key:
        headers.update({'X-API-KEY': response_api_key})

    # cookie
    cookie = responses.headers.get('Set-Cookie')
    if cookie:
        headers.update({'Cookie': cookie})

    return headers
    



"""
request code
"""

## NEW: add headers
def send_request(path, method, base_url, yaml_data, proxy, auth_data, headers = {}):
    status = 0

    # TODO see if there is more info in the headers (content type / accept type )
    post_data = {}
    method_data = yaml_data['paths'][path][method]
                
    # add all parameters
    path_query = ''
    if 'parameters' in method_data:
        for parameter in method_data['parameters']:

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
                    insertval = [fuzzer(parameter['schema']['items']['type'])]
            else:
                insertval = fuzzer(parameter['schema']['type'])
            
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
                if '$ref' in form_details['schema']:
                    ref = form_details['schema']['$ref']
                    body_schema = get_referenced_schema(yaml_data,ref)
                    post_data = generate_data_from_schema(yaml_data,body_schema)
                elif form_details['schema']['type'] == 'array':
                    if '$ref' in form_details['schema']['items']:
                        ref = form_details['schema']['items']['$ref']
                        body_schema = get_referenced_schema(yaml_data,ref)
                        post_data = [generate_data_from_schema(yaml_data,body_schema)]
                    else:
                        post_data = [fuzzer(form_details['schema']['type'])]
                else:
                    post_data  = fuzzer(form_details['schema']['type'])
    
    try:
        # print(endpoint_url)
        # print(headers)
        # print(post_data)
        if method == 'get':
            response_get = requests.get(endpoint_url, proxies=proxy, headers=headers,verify=False)     # TODO authentication
        elif method == 'delete':
            response_get = requests.delete(endpoint_url, proxies=proxy,headers=headers,verify=False) 
        elif method == 'post':
            response_get = requests.post(endpoint_url, proxies=proxy, headers=headers, json=post_data,verify=False)   
        elif method == 'put':
            response_get = requests.put(endpoint_url, proxies=proxy, headers=headers, json=post_data,verify=False)
        elif method == 'options':
            response_get = requests.post(endpoint_url, proxies=proxy,headers=headers,verify=False)
        status = response_get.status_code
        if str(status).startswith('5'):
            print('HTTP/1.1 ', status, 'Internal Error')
            return response_get
    except requests.exceptions.RequestException as e:
        print('Error', e)
        return e

    return response_get

    
    

class CommandLine:
    def __init__(self):
        parser = argparse.ArgumentParser(description = "Parser to read inputs for swagger_conv")
        parser.add_argument("swagger_file", help = 'Swagger file to read, yaml or json')
        # need to change to auth
        parser.add_argument("-a", "--auth_json", help = "Authorization data", required = False, default = None)
        parser.add_argument("-p", "--proxy", help = "Proxy Server to run on", required = False)
        parser.add_argument("-f", "--fuzz_times", help = "Number of times to fuzz", required = False, default = 0)
        
        argument = parser.parse_args()
        convolute_api(argument.swagger_file, argument.proxy, int(argument.fuzz_times), argument.auth_json)
        

if __name__ == '__main__':
    app = CommandLine()
    #  convolute_api('examples/openapi.json', None, 0, 'examples/auth.json')
    #  python3 swagger_conv.py examples/openapi.json -a examples/auth.json
    