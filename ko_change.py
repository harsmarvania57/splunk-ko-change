from __future__ import print_function
from builtins import input
from io import open
import os
import sys
from splunk import mergeHostPath
import splunk.rest as rest
import splunk.auth as auth
import splunk.entity as entity
import json
import argparse
import getpass
import re


ko_details = []

# Argument parser
def argument_parser():
    try:
        parser = argparse.ArgumentParser(description='List/Transfer ownership/permission of splunk knowledge objects.')
        subparsers = parser.add_subparsers(dest='subp_flag', help='Command Choices')
        
        # Create argument parser to list the data
        list_parser = subparsers.add_parser('list', help='List splunk knowledge objects')
        if sys.version_info[0] < 3:
            list_ko_subparser = list_parser.add_subparsers(dest='list_ko_name', help='Knowledge Object Choices')
        else:
            list_ko_subparser = list_parser.add_subparsers(dest='list_ko_name', required=True, help='Knowledge Object Choices')
        
        # Create argument parser for change permission of Knowledge objects
        change_parser = subparsers.add_parser('change', help='Change ownership, read & write permission and sharing of splunk knowledge objects')
        if sys.version_info[0] < 3:
            change_ko_subparser = change_parser.add_subparsers(dest='change_ko_name', help='Knowledge Object Choices')
        else:
            change_ko_subparser = change_parser.add_subparsers(dest='change_ko_name', required=True, help='Knowledge Object Choices')
        
        # Create argument parser for move of Knowledge objects 
        move_parser = subparsers.add_parser('move', help='Move knowledge objects to another app')
        if sys.version_info[0] < 3:
            move_ko_subparser = move_parser.add_subparsers(dest='move_ko_name', help='Knowledge Object Choices')
        else:
            move_ko_subparser = move_parser.add_subparsers(dest='move_ko_name', required=True, help='Knowledge Object Choices')
        
        ko_type_args = ['macro', 'savedsearch', 'dashboard', 'lookupdef', 'lookupfile', 'tag', 'field_extraction', 'panel', 'field_transformation', 'workflow_action']
        
        for i in ko_type_args:
            lkp = list_ko_subparser.add_parser(i, help='To list ' + i)
            lkp_grp = lkp.add_mutually_exclusive_group(required=True)
            lkp_grp.add_argument('--user', required=False, help='Username')
            lkp_grp.add_argument('--file', required=False, help='Filename containing KO title')
            lkp.add_argument('--filter', required=False, help='Filter by name', action='append')
            lkp.add_argument('--host', required=False, help='Specify splunk server to connect to (defaults to local server)')
            lkp.add_argument('--count', required=False, help='Number of KO to pull in single request (default 30)', default=30)
            ckp = change_ko_subparser.add_parser(i, help='To change acl of ' + i)
            ckp_grp = ckp.add_mutually_exclusive_group(required=True)
            ckp_grp.add_argument('--olduser', required=False, help='Old Username')
            ckp_grp.add_argument('--file', required=False, help='Filename containing KO title')
            ckp.add_argument('--filter', required=False, help='Filter by name', action='append')
            ckp.add_argument('--host', required=False, help='Specify splunk server to connect to (defaults to local server)')
            ckp.add_argument('--count', required=False, help='Number of KO to pull in single request (default 30)', default=30)
            ckp.add_argument('--newuser', required=False, help='New Username')
            ckp.add_argument('--sharing', required=False, help='New Sharing Permission')
            ckp.add_argument('--readperm', required=False, help='New Read Permission of KO')
            ckp.add_argument('--writeperm', required=False, help='New Write Permission of KO')
            mkp = move_ko_subparser.add_parser(i, help='To move ' + i + ' to another app')
            mkp_grp = mkp.add_mutually_exclusive_group(required=True)
            mkp_grp.add_argument('--user', required=False, help='Username')
            mkp_grp.add_argument('--file', required=False, help='Filename containing KO title')
            mkp.add_argument('--filter', required=False, help='Filter by name', action='append')
            mkp.add_argument('--host', required=False, help='Specify splunk server to connect to (defaults to local server)')
            mkp.add_argument('--count', required=False, help='Number of KO to pull in single request (default 30)', default=30)
            mkp.add_argument('--newapp', required=True, help='Move KO to specified app')
            
        # Print help if no option provided
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)
            
        args = parser.parse_args()
        
        if args.subp_flag == 'list':
            return args.subp_flag, args.list_ko_name, args.host, args.filter, args.count, args.user, args.file
        elif args.subp_flag == 'change':
            if (args.newuser != None or args.sharing != None or args.readperm != None or args.writeperm != None):
                if args.sharing == 'user' and (args.readperm != None or args.writeperm != None):
                    parser.error('You can\'t supply --readperm or --writeperm or both with --sharing user')
                else:
                    return args.subp_flag, args.change_ko_name, args.host, args.filter, args.count, args.olduser, args.file, args.newuser, args.sharing, args.readperm, args.writeperm
            elif (args.newuser is None and args.sharing is None and args.readperm is None and args.writeperm is None):
                parser.error('Atleast one argument is required (--newuser, --sharing, --readperm, --writeperm)')
        elif args.subp_flag == 'move':
            return args.subp_flag, args.move_ko_name, args.host, args.filter, args.count, args.user, args.file, args.newapp
        
    except:
        raise

def user_check(ko_type=None, new_owner=None):
    try:
        print('Authentication method:\n1.) Username and Password\n2.) Auth token')
        auth_method = input('Please select authentication method (Enter 1 or 2): ')
        if auth_method == '1':
            username = os.environ.get('splunkusername','')
            if username == '':
                username = input('Enter username with admin privileges: ')
            password = os.environ.get('splunkpassword','')
            if password == '':
                password = getpass.getpass('Enter password: ')
            session_key = auth.getSessionKey(username, password)
        elif auth_method == '2':
            session_key = getpass.getpass('Enter token: ')
        else:
            print('Please respond with 1 or 2')
            sys.exit(1)
        
        # Check new owner exist or not
        if ko_type == 'change':
            if new_owner:
                userlist = auth.getUser(name=new_owner, sessionKey=session_key)
                if not userlist:
                    print('New owner {0} not found in splunk'.format(new_owner))
                    sys.exit(1)
        return session_key
    except:
        raise

# Check Role
def role_check(role):
    try:
        getrole = auth.listRoles(count=0)
        if role not in getrole:
            print('Role {0} not found in splunk'.format(role))
            sys.exit(1)
        return True
    except:
        raise
        
# Check app
def app_check(app, session_key):
    try:
        getapp = list(entity.getEntities('apps/local', search='visible=1 AND disabled=0', namespace=None, count=-1, sessionKey=session_key).keys())
        
        if app not in getapp:
            print('App {0} not found in splunk'.format(app))
            sys.exit(1)
        return True
    except:
        raise

# Filter and retrieve value from each knowledge object
def ko_filter(ko_name, ko_details, ko_config, ko_payload, instance_type, splunk_version):
    author_name = ko_config[ko_payload]['author']
    ko_title = ko_config[ko_payload]['name']
    sharing = ko_config[ko_payload]['acl']['sharing']
    app_name = ko_config[ko_payload]['acl']['app']
    list_url = ko_config[ko_payload]['links']['list']
    if ko_name == 'savedsearch':
        orphan = str(ko_config[ko_payload]['content']['orphan'])
    else:
        orphan = 'N/A'
                
    if ko_config[ko_payload]['acl']['perms'] is not None:
        if 'read' in ko_config[ko_payload]['acl']['perms']:
            read_perm = ','.join(ko_config[ko_payload]['acl']['perms']['read'])
        else:
            read_perm = 'None'
                    
        if 'write' in ko_config[ko_payload]['acl']['perms']:
            write_perm = ','.join(ko_config[ko_payload]['acl']['perms']['write'])
        else:
            write_perm = 'None'
    else:
        read_perm = 'None'
        write_perm = 'None'
                
    if (instance_type == 'cloud' and splunk_version >= (8, 2, 2109)) or (instance_type is None and ((splunk_version >= (8, 1, 7) and splunk_version < (8, 2, 0)) or (splunk_version >= (8, 2, 3)))):
        ko_details.append([app_name, author_name, ko_title, ko_name, list_url, sharing, read_perm, write_perm, orphan])
    else:
        if not ((ko_name == 'field_extraction' and sharing == 'user') or (ko_name == 'tag' and sharing == 'user')):
            ko_details.append([app_name, author_name, ko_title, ko_name, list_url, sharing, read_perm, write_perm, orphan])


# Retrieve knowledge objects for user
def retrieve_content(session_key, ko_name, owner, count, file=None, filter=None):
    try:
        # For Saved Searches
        if ko_name == 'macro':
            config_endpoint = '/servicesNS/-/-/configs/conf-macros'
        # For Saved Searches
        if ko_name == 'savedsearch':
            config_endpoint = '/servicesNS/-/-/saved/searches'
        # For Dashboards
        elif ko_name == 'dashboard':
            config_endpoint = '/servicesNS/-/-/data/ui/views'
        # For Lookup Definitions
        elif ko_name == 'lookupdef':
            config_endpoint = '/servicesNS/-/-/data/transforms/lookups'
        # For Lookup Files
        elif ko_name == 'lookupfile':
            config_endpoint = '/servicesNS/-/-/data/lookup-table-files'
        # For Tags
        elif ko_name == 'tag':
            config_endpoint = '/servicesNS/-/-/saved/fvtags'
        # For Field Extractions	
        elif ko_name == 'field_extraction':
            config_endpoint = '/servicesNS/-/-/data/props/extractions'
        # For Panels
        elif ko_name == 'panel':
            config_endpoint = '/servicesNS/-/-/data/ui/panels'
        # For Field Transformations
        elif ko_name == 'field_transformation':
            config_endpoint = '/servicesNS/-/-/data/transforms/extractions'
        # For Workflow Actions
        elif ko_name == 'workflow_action':
            config_endpoint = '/servicesNS/-/-/data/ui/workflow-actions'
        
        # Get Argument
        if ko_name == 'savedsearch':
            get_argument = {'output_mode': 'json', 'count': count, 'offset': 0, 'add_orphan_field': 'yes', 'f': 'title', 'f': 'orphan'}
        else:
            get_argument = {'output_mode': 'json', 'count': count, 'offset': 0, 'f': 'title'}
        
        if filter:
            get_argument = json.loads(json.dumps(get_argument))
            get_argument['search'] = filter

        # Fetch knowledge objects from Splunk using REST API with pagination
        (response, content) = rest.simpleRequest(config_endpoint, session_key, getargs=get_argument)
        json_content = json.loads(content)
        total_count = json_content['paging']['total']
        ko_config = []
        content_length = 0
        for i in json_content['entry']:
            ko_config.append(i)
            content_length += 1
        print('Fetched {0} out of total {1} knowledge objects.'.format(content_length, total_count))
        offset = count
        while offset < total_count:
            content_length = 0
            get_argument['offset'] = offset
            (response, content) = rest.simpleRequest(config_endpoint, session_key, getargs=get_argument)
            json_content = json.loads(content)
            for i in json_content['entry']:
                ko_config.append(i)
                content_length += 1
            print('Fetched {0} out of total {1} knowledge objects.'.format(offset + content_length, total_count))
            offset = offset + count
    except:
        raise
   
    ko_details.append(['App Name', 'Author Name', 'Title', 'Type of KO', 'List URL', 'Sharing', 'Read Perm', 'Write Perm', 'Orphan'])
    ko_details.append(['===========', '===========', '===========', '===========', '===========', '===========', '===========', '===========', '==========='])

    #Pull Splunk version and host
    (response, content) = rest.simpleRequest('/services/server/info', session_key, getargs={'output_mode': 'json'})
    json_content = json.loads(content)
    if 'instance_type' in json_content['entry'][0]['content']:
        instance_type = json_content['entry'][0]['content']['instance_type']
    else:
        instance_type = None
    splunk_version = tuple(map(int, (json_content['entry'][0]['content']['version']).split('.')))

    # Search knowledge objects for user from all users output and append into ko_details list.
    for i in range(len(ko_config)):
        if owner:
            #author_name = ko_config[i]['author']
            #if author_name == owner :
            #    ko_filter(ko_name, ko_details, ko_config, i, instance_type, splunk_version)
            ko_filter(ko_name, ko_details, ko_config, i, instance_type, splunk_version)

    
        if file:
            with open(file, encoding='utf-8') as read_f:
                f_content = read_f.read().splitlines()
            for f_title in f_content:
                ko_title = ko_config[i]['name']
                if f_title == ko_title:
                    ko_filter(ko_name, ko_details, ko_config, i, instance_type, splunk_version)
    
    # Check if user have any knowledge object or not and then print message and exit the script if no knowledge objects found.
    if len(ko_details) <= 2 :
        print('No {0} found'.format(ko_name))
        sys.exit(1)
    else:
        print('\n--------------------------------')
        print('Total {0} {1} found'.format(len(ko_details)-2,ko_name))
        print('--------------------------------')
        col_array = []

        # Searching maximum length for every row in each column and adding 2 for padding & store them into col_array list
        for col in zip(*ko_details):
            col_width = max(len(string) for string in col) + 2
            col_array.append(col_width)
        
        # Print ko_details list and inogre 4th column "List URL" while printing
        for row in ko_details:
            j = 0
            print('')
            for index, string in enumerate(row):
                if index != 4:
                    print(''.join(string.ljust(col_array[j])), end=' ')
                j = j + 1
                
        print('\n')
        return ko_details, col_array

# Change permission of knowledge objects 
def change_permission(session_key, ko_name, old_owner, new_owner, count, file=None, filter=None, new_sharing=None, new_readperm=None, new_writeperm=None):
    try:
        # Retrieve knowledge objects
        (ko_details, col_array) = retrieve_content(session_key, ko_name, old_owner, count, file, filter)
        user_input = input('Do you want to change now?[y/n] ').lower()
        
        if user_input == 'y':
            col_array.append(9)
            # Append new column "Status" in ko_details list. 
            ko_details[0].append('Status')
            ko_details[1].append('========')
            
            # Print first 2 array from ko_details and ignore 4th column "List URL" while printing.
            for row in ko_details[:2]:
                j = 0
                print('')
                for index, string in enumerate(row):
                    if index != 4:
                        print(''.join(string.ljust(col_array[j])), end=' ')
                    j = j + 1
			
            # Change permission and print column starting from 3rd array and ignore 4th column "List URL" while printing.
            for row in ko_details[2:]:
                #app_name = row[0]
                author_name = row[1]
                #ko_title = row[2]
                list_url = row[4]
                sharing = row[5]
                read_perm = row[6]
                write_perm = row[7]
                orphan = row[8]
                
                if new_owner:
                    if new_sharing:
                        if new_sharing != 'user':
                            if new_readperm:
                                if new_writeperm:
                                    post_argument = {'sharing': new_sharing, 'owner': new_owner, 'perms.read': new_readperm, 'perms.write': new_writeperm}
                                else:
                                    if write_perm == 'None':
                                        post_argument = {'sharing': new_sharing, 'owner': new_owner, 'perms.read': new_readperm}
                                    else:
                                        post_argument = {'sharing': new_sharing, 'owner': new_owner, 'perms.read': new_readperm, 'perms.write': write_perm}
                            elif new_writeperm:
                                if read_perm == 'None':
                                    post_argument = {'sharing': new_sharing, 'owner': new_owner, 'perms.write': new_writeperm}
                                else:
                                    post_argument = {'sharing': new_sharing, 'owner': new_owner, 'perms.read': read_perm, 'perms.write': new_writeperm}
                            else:
                                post_argument = {'sharing': new_sharing, 'owner': new_owner}
                        else:
                            post_argument = {'sharing': new_sharing, 'owner': new_owner}
                    elif new_readperm:
                        if new_writeperm:
                            post_argument = {'sharing': sharing, 'owner': new_owner, 'perms.read': new_readperm, 'perms.write': new_writeperm}
                        else:
                            if write_perm == 'None':
                                post_argument = {'sharing': sharing, 'owner': new_owner, 'perms.read': new_readperm}
                            else:
                                post_argument = {'sharing': sharing, 'owner': new_owner, 'perms.read': new_readperm, 'perms.write': write_perm}
                    elif new_writeperm:
                        if read_perm == 'None':
                            post_argument = {'sharing': sharing, 'owner': new_owner, 'perms.write': new_writeperm}
                        else:
                            post_argument = {'sharing': sharing, 'owner': new_owner, 'perms.read': read_perm, 'perms.write': new_writeperm}
                    else:
                        post_argument = {'sharing': sharing, 'owner': new_owner}
                elif new_sharing:
                    if new_sharing != 'user':
                        if new_readperm:
                            if new_writeperm:
                                post_argument = {'sharing': new_sharing, 'owner': author_name, 'perms.read': new_readperm, 'perms.write': new_writeperm}
                            else:
                                if write_perm == 'None':
                                    post_argument = {'sharing': new_sharing, 'owner': author_name, 'perms.read': new_readperm}
                                else:
                                    post_argument = {'sharing': new_sharing, 'owner': author_name, 'perms.read': new_readperm, 'perms.write': write_perm}
                        elif new_writeperm:
                            if read_perm == 'None':
                                post_argument = {'sharing': new_sharing, 'owner': author_name, 'perms.write': new_writeperm}
                            else:
                                post_argument = {'sharing': new_sharing, 'owner': author_name, 'perms.read': read_perm, 'perms.write': new_writeperm}
                        else:
                            post_argument = {'sharing': new_sharing, 'owner': author_name}
                    else:
                        post_argument = {'sharing': new_sharing, 'owner': author_name}
                elif new_readperm:
                    if new_writeperm:
                        post_argument = {'sharing': sharing, 'owner': author_name, 'perms.read': new_readperm, 'perms.write': new_writeperm}
                    else:
                        if write_perm == 'None':
                            post_argument = {'sharing': sharing, 'owner': author_name, 'perms.read': new_readperm}
                        else:
                            post_argument = {'sharing': sharing, 'owner': author_name, 'perms.read': new_readperm, 'perms.write': write_perm}
                elif new_writeperm:
                    if read_perm == 'None':
                        post_argument = {'sharing': sharing, 'owner': author_name, 'perms.write': new_writeperm}
                    else:
                        post_argument = {'sharing': sharing, 'owner': author_name, 'perms.read': read_perm, 'perms.write': new_writeperm}
                    
                
                try:
                    if ko_name == 'savedsearch' and orphan == 'True':
                        list_url = re.sub(r'^((?:[^\/]*\/){2})(?:[^\/]*)(\/.*)', r'\1nobody\2', list_url)
                        post_argument = json.loads(json.dumps(post_argument))
                        post_argument['add_orphan_field'] = 'yes'
                    acl_url = list_url + '/acl'
                    rest.simpleRequest(acl_url, sessionKey=session_key, postargs=post_argument, method='POST', raiseAllErrors=True)
                    # Fetching index for value in list and append value
                    data_index = ko_details.index(row)
                    ko_details[data_index].append('Changed')
                    ko_array_value = ko_details[data_index]
                    j = 0
                    print('')
                    
                    for index, string in enumerate(ko_array_value):
                        if index != 4:
                            print(''.join(string.ljust(col_array[j])), end=' ')
                        j = j + 1
                except:
                    data_index = ko_details.index(row)
                    ko_details[data_index].append('Failed')
                    ko_array_value = ko_details[data_index]
                    j = 0
                    print('')
                    
                    for index, string in enumerate(ko_array_value):
                        if index != 4:
                            print(''.join(string.ljust(col_array[j])), end=' ')
                        j = j + 1
                    raise
            print('\n')
        elif user_input == 'n':
            sys.exit(1)
        else:
            print ("Please respond with 'y' or 'n'")
    except:
        raise
        

# Move knowledge objects from one app to another app
def move_app(session_key, ko_name, owner, count, file=None, filter=None, new_appname=None):
    try:
        # Retrieve knowledge objects
        (ko_details, col_array) = retrieve_content(session_key, ko_name, owner, count, file, filter)
        user_input = input('Do you want to move now?[y/n] ').lower()
        
        if user_input == 'y':
            col_array.append(9)
            # Append new column "Status" in ko_details list. 
            ko_details[0].append('Status')
            ko_details[1].append('========')
            
            # Print first 2 array from ko_details and ignore 4th column "List URL" while printing.
            for row in ko_details[:2]:
                j = 0
                print('')
                for index, string in enumerate(row):
                    if index != 4:
                        print(''.join(string.ljust(col_array[j])), end=' ')
                    j = j + 1
			
            # Move app and print column starting from 3rd array and ignore 4th column "List URL" while printing.
            for row in ko_details[2:]:
                #app_name = row[0]
                author_name = row[1]
                #ko_title = row[2]
                list_url = row[4]
                sharing = row[5]
                
                mv_url = list_url + '/move'
                if new_appname and sharing == 'user':
                    post_argument = {'user': author_name, 'app': new_appname}
                else:
                    post_argument = {'user': 'nobody', 'app': new_appname}
                
                try:
                    rest.simpleRequest(mv_url, sessionKey=session_key, postargs=post_argument, method='POST', raiseAllErrors=True)
                    # Fetching index for value in list and append value
                    data_index = ko_details.index(row)
                    ko_details[data_index].append('Moved')
                    ko_array_value = ko_details[data_index]
                    j = 0
                    print('')
                    
                    for index, string in enumerate(ko_array_value):
                        if index != 4:
                            print(''.join(string.ljust(col_array[j])), end=' ')
                        j = j + 1
                except:
                    data_index = ko_details.index(row)
                    ko_details[data_index].append('Failed')
                    ko_array_value = ko_details[data_index]
                    j = 0
                    print('')
                    
                    for index, string in enumerate(ko_array_value):
                        if index != 4:
                            print(''.join(string.ljust(col_array[j])), end=' ')
                        j = j + 1
                    raise
            print('\n')
        elif user_input == 'n':
            sys.exit(1)
        else:
            print ("Please respond with 'y' or 'n'")
    except:
        raise

def main():
    # Call argument_parser function and store returned value into ko_value variable
    ko_value = argument_parser()

    if ko_value[2]!="":
        mergeHostPath(ko_value[2], True)
    
    ko_type = ko_value[0]
    ko_name = ko_value[1]
    filter = ko_value[3]
    count = int(ko_value[4])
    owner = ko_value[5]
    file = ko_value[6]
    if owner is not None:
        if filter is None:
            filter = ['eai:acl.owner={0}'.format(owner)]
        else:
            filter.append('eai:acl.owner={0}'.format(owner))

    # Retrieve knowledge objects
    if ko_type == 'list':
        session_key = user_check(ko_type)
        retrieve_content(session_key, ko_name, owner, count, file, filter)
    elif ko_type == 'change':
        new_owner = ko_value[7]
        sharing = ko_value[8]
        read_perm = ko_value[9]
        write_perm = ko_value[10]
        session_key = user_check(ko_type, new_owner)

        if read_perm:
            if ',' in read_perm:
                r_perm = read_perm.split(',')
            else:
                r_perm = read_perm.split(' ')

        if write_perm:
            if ',' in write_perm:
                w_perm = write_perm.split(',')
            else:
                w_perm = write_perm.split(' ')

        # Check whether role exist or not for Read and Write permission
        if read_perm and write_perm:
            for readrole in r_perm:
                if readrole != '*':
                    role_check(readrole)
                else:
                    if len(r_perm) > 1:
                        print ('You can\'t supply \'*\' with any other role in read permission')
                        sys.exit(1)
            for writerole in w_perm:
                if writerole != '*':
                    role_check(writerole)
                else:
                    if len(w_perm) > 1:
                        print ('You can\'t supply \'*\' with any other role in write permission')
                        sys.exit(1)
        elif read_perm:
            for readrole in r_perm:
                if readrole != '*':
                    role_check(readrole)
                else:
                    if len(r_perm) > 1:
                        print ('You can\'t supply \'*\' with any other role in read permission')
                        sys.exit(1)
        elif write_perm:
            for writerole in w_perm:
                if writerole != '*':
                    role_check(writerole)
                else:
                    if len(w_perm) > 1:
                        print ('You can\'t supply \'*\' with any other role in write permission')
                        sys.exit(1)
                
        change_permission(session_key, ko_name, owner, new_owner, count, file, filter, sharing, read_perm, write_perm)
    elif ko_type == 'move':
        new_appname = ko_value[7]
        session_key = user_check(ko_type)

        if new_appname:
            app_check(new_appname, session_key)
        
        move_app(session_key, ko_name, owner, count, file, filter, new_appname)
		
if __name__ == '__main__':
    try:
        main()
    except:
        raise