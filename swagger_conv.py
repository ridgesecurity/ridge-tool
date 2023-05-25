import yaml
import requests
import json
import argparse

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
    if auth_api_calls:
        for calls in auth_api_calls:
            path = calls['path']
            method = calls['method']
            print(path)
            print(method)

            output = send_request(path, method, base_url, yaml_data, proxies, auth_data)
            
            if type(output) == dict:
                for keys,values in output.items():
                    print(keys)
                    print(values)
            else:
                print(output)
            print('------')
            
            auth_excuted.append([path,method])


    for path, path_data in yaml_data['paths'].items():
        for method in path_data.keys():
            if [path,method] in auth_excuted:
                # ignore the calls that have been excuted
                continue
            else:
                print(path)
                print(method)
                output = send_request(path, method, base_url, yaml_data, proxies, auth_data)
            
            if type(output) == dict:
                for keys,values in output.items():
                    print(keys)
                    print(values)
            else:
                print(output)
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
                        'method': method,
                        'sec_name': method_yaml_data['security']
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
    fuzz_dic = {'integer':1, 'string':'sold', 'array':['tag1'],'boolean':True,'object':{},'number':3.14}
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
        
        if 'example' in property_data:
            json_data[property_name] = property_data.get('example')
        elif '$ref' in property_data:
            ref =  property_data.get('$ref')
            ref_schema = get_referenced_schema(yaml_data,ref)
            json_data = generate_data_from_schema(yaml_data,ref_schema)
        else:
            data_type = property_data.get('type')
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
        add_header = auth_details['name'] + auth_details['value']
        if auth_details.get('in','cookie'):
            header['Set-Cookie'] = add_header
        else:
            header['Authorization'] = add_header
    
    return header



"""
request code
"""


def send_request(path, method, base_url, yaml_data, proxy, auth_data):
    status = 0

    # TODO see if there is more info in the headers (content type / accept type / authentication)
    # TODO? add cookie
    headers = {}
    params = {}
    method_data = yaml_data['paths'][path][method]
                
    # add all parameters
    if 'parameters' in method_data:
        for parameter in method_data['parameters']:
            para_name = parameter['name']
            fuzzval = fuzzer(parameter['schema']['type'])
            
             # chece if the parameter is in path or in query
            if parameter['in'] == 'query':
                params[para_name] = fuzzval
            elif parameter['in'] == 'path':
                placeholder = '{' + para_name + '}'
                path = path.replace(placeholder, str(fuzzval))
            elif parameter['in'] == 'header':
                if para_name in auth_data.keys():
                    headers = add_to_header(headers,auth_data[para_name])
                else:
                    headers[para_name] = fuzzval

            # elif parameter['in'] == 'header':
            #     if para_name == 'api_key':
            #         headers[para_name] = api_key
            #     else:
            #         headers[para_name] = fuzzval

        
    endpoint_url = base_url+path

    # generate request body
    if method in ['post', 'put']:
        post_data = {}
        if 'requestBody' in method_data:
            request_body = method_data['requestBody']
            if request_body.get('required', False):    
                request_data = request_body['content']
                for _, form_details in request_data.items():
                    if '$ref' in form_details['schema']:
                        ref = form_details['schema']['$ref']
                        body_schema = get_referenced_schema(yaml_data,ref)
                        post_data = generate_data_from_schema(yaml_data,body_schema)
                    else:
                        post_data  = fuzzer(form_details['schema']['type'])
        data = {**params, **post_data}

    try:
        if method == 'get':
            response_get = requests.get(endpoint_url, proxies=proxy, params=params,verify=False)     # TODO authentication
        elif method == 'delete':
            response_get = requests.delete(endpoint_url, proxies=proxy,headers=headers,verify=False) 
        elif method == 'post':
            response_get = requests.post(endpoint_url, proxies=proxy, data=data,verify=False)   
        elif method == 'put':
            response_get = requests.put(endpoint_url, proxies=proxy, data=data,verify=False)
        status = response_get.status_code
        if str(status).startswith('5'):
            print('HTTP/1.1 ', status, 'Internal Error')
            return []
    except requests.exceptions.RequestException as e:
        print('Error', e)
        return e

    if not str(status).startswith('5'):
        output = {}
        output.update({'url':response_get.request.url})
        output.update({'headers':response_get.request.headers})
        
        if is_json(response_get.content):
            get_data = response_get.json()
        else:
            get_data = response_get.content
        output.update({'content':get_data})
    
    return output
    
    

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
    #convolute_api('examples/openapi.json', None, 0, 'examples/auth.json')
    