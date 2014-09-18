#!/usr/bin/env python
import argparse
import subprocess
import os
import plistlib
import logging
import sys

def dscl_create(lusername,lkey="",lvalue="",password=False):
    import subprocess
    dsclCommand=["/usr/bin/dscl"]
    dsclCommand.extend(["."])
    if password:
        dsclCommand.extend(["-passwd"])
    else:
        dsclCommand.extend(["-create"])
    dsclCommand.extend(["/Users/{}".format(lusername)])
    if len(lkey) > 0:
        dsclCommand.extend([lkey])
    if len(lvalue) > 0:
        dsclCommand.extend([lvalue])
    #print dsclCommand
    if subprocess.call(dsclCommand,shell=False):
        logging.error( "Creating {} : FAILED".format(lkey))
        return False
    else:
        logging.info("Creating {} : Succeeded!".format(lkey))
        return True

def check_user_exists(lusername):
    import subprocess
    import os
    devnull = open(os.devnull, 'w')
    checkCommand=["/usr/bin/dscl","-plist", ".","-read", "/Users/{}".format(lusername)]
    if subprocess.call(checkCommand,stdout=devnull, stderr=devnull):
        return False
    else:
        return True


def add_user_to_group(lusername,lgroup):
    import subprocess
    import os
    devnull = open(os.devnull, 'w')
    group_add_command=["/usr/sbin/dseditgroup","-o", "edit","-n",".","-a", lusername,"-t","user",lgroup]
    if subprocess.call(group_add_command,stdout=devnull, stderr=devnull):
        return False
    else:
        return True

def set_password_policy(lusername,lpolicy):
    import subprocess
    import os
    devnull = open(os.devnull, 'w')
    group_add_command=["/usr/bin/pwpolicy","-u",lusername,"-setpolicy","\"{}\"".format(lpolicy)]
    if subprocess.call(group_add_command,stdout=devnull, stderr=devnull):
        return False
    else:
        return True

def create_user(user_name,user_UID,user_GID,user_RealName,password):
    try:
        dscl_create(user_name)
        dscl_create(user_name,"dsAttrTypeNative:_defaultLanguage","en")
        dscl_create(user_name,"dsAttrTypeNative:_writers_passwd",user_name)
        dscl_create(user_name,"dsAttrTypeNative:_writers_jpegphoto",user_name)
        dscl_create(user_name,"dsAttrTypeNative:_writers_picture",user_name)
        dscl_create(user_name,"dsAttrTypeNative:_writers_UserCertificate",user_name)
        dscl_create(user_name,"dsAttrTypeNative:_writers_realname",user_name)
        dscl_create(user_name,"UserShell","/bin/bash")
        dscl_create(user_name,"UniqueID",user_UID)
        dscl_create(user_name,"PrimaryGroupID",user_GID)
        dscl_create(user_name,"RealName",user_RealName)
        dscl_create(user_name,password,password=True)
        dscl_create(user_name,"NFSHomeDirectory","/Users/{}".format(user_name))
        dscl_create(user_name,"AuthenticationHint","Enter your standard Sanger password")
    except Exception as e:
        logging.error("That went wrong: {}".format(e))


def create_home_folder(path_prefix,user_name):
    import subprocess
    import os
    home_dir_path = os.path.join(path_prefix,user_name)
    devnull = open(os.devnull, 'w')
    if os.path.isdir(home_dir_path):
        logging.info("Home directory already exists. chowning it for good measure")
        chown_command=['/usr/sbin/chown','-R',user_name,home_dir_path]
        try:
            subprocess.call(chown_command,stdout=devnull, stderr=devnull)
        except:
            logging.error("Unable to chown homedir")
    else:
        create_homedir_command =["/usr/sbin/createhomedir","-c","-u",user_name]
        logging.info("Creating home directory for {}".format(user_name))
        try:
            subprocess.call(create_homedir_command,stdout=devnull, stderr=devnull)
        except Exception as e:
            logging.error("Unable to create homedir: {}".format(e))


def delete_user(luser):
    import subprocess
    import os
    devnull = open(os.devnull, 'w')
    delete_user_command =["/usr/bin/dscl",".","-delete","/Users/{}".format(luser)]
    try:
        subprocess.call(delete_user_command,stdout=devnull, stderr=devnull)
    except Exception as e:
        logging.critical("Unable to delete {}".format(luser))
        exit()

def get_local_uids():
    import subprocess
    import string
    import logging
    returnList=[]
    dscl_command=["/usr/bin/dscl"]
    dscl_command.extend(["."])
    dscl_command.extend(["-list"])
    dscl_command.extend(["/Users"])
    dscl_command.extend(["UniqueID"])
    try:
        uid_list = subprocess.check_output(dscl_command,shell=False)
    except:
        logging.critical("Unable to get a list of current UIDs")
        exit()
    for UID in uid_list.splitlines(False):
        line_list=UID.split(None,1)
        if int(line_list[1]) > 500:
            returnList.extend([int(line_list[1])])
    return returnList

def get_new_unused_uid(list_o_UIDS):
    import logging
    try_id=501
    max_UID=600
    while try_id < max_UID:
        if not try_id in list_o_UIDS:
            return try_id
        try_id+=1
    logging.critical("Unable to get a new UID")
    return None



#### Do stuff
if __name__ == '__main__':

    if os.getuid() != 0:
        print("This has to be run as root")
        exit()

    ###### Defaults
    # List containing each group the account should be added to
    standardGroupList=["staff","_lpadmin"]
    # Full path to the log file
    logfile = "/Library/Logs/create_local_users.log"
    # String containing the password policy settings.
    # See man pwpolicy for details
    password_policy="requiresAlpha=1 requiresNumeric=1 minChars=8 maxChars=20 newPasswordRequired=1"
    # Default password that new accounts will get
    default_password="123456"
    # Default GID the users will get
    default_group="20"
    ######

    # Command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-v","--verbose", help="spew lots of text on the console",action="store_true")
    parser.add_argument("-u","--username", help="The username(s) of the account to create. Multiple users should be specified as a list separated by a space",nargs='+')
    parser.add_argument("-a","--admin",help="The user(s) specified with --username will be made as admin. Note: this setting will apply to all users specified in this run",action="store_true")
    parser.add_argument("-f","--force",help="Delete and re-create users that already exist on the system. This will not alter the homefolder - just the user account",action="store_true")
    parser.add_argument("-p","--plist",help="Read list of users from a plist file. e.g. --plist /Library/Preferences/uk.ac.sanger.userlist.plist. If specified then the --username and --admin switches are ignored.")
    args = parser.parse_args()

    # Setup logging and level
    logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s',filename=logfile,level=logging.DEBUG)

    # Print everything to the console too
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)-8s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

    # Check if we're using a plist. If not try to read the username
    if args.plist:
        # Check the plist exists
        if not os.path.isfile(args.plist):
            logging.critical(args.plist,"does not exist. Exiting")
            exit()
        else:
            pl = plistlib.readPlist(args.plist)
            usernames_to_create=pl["user_list"]
    else:
        # Setup username
        usernames_to_create=[]
        if args.username:
            for user in args.username:
                build_user={}
                build_user["userid"]=user
                build_user["admin"]=args.admin
                usernames_to_create.append(build_user.copy())

        else:
            logging.critical("No username specified. Exiting")
            exit()
    #
    # Main loop
    #
    for username_to_create in usernames_to_create:
        user_info={}
        user_info['RealName']=username_to_create["userid"]
        user_info['UID']=str(get_new_unused_uid(get_local_uids()))
        user_info['GID']=default_group

        # Check if account exists on machine
        if check_user_exists(username_to_create["userid"]):
            if args.force:
                logging.warning("{} already exists. Deleting!".format(username_to_create["userid"]))
                delete_user(username_to_create["userid"])
            else:
                logging.warning("{} already exists. Skipping".format(username_to_create["userid"]))
                continue

        # Actually create the user account
        logging.info("Creating {0} ({1})".format(user_info['RealName'],username_to_create["userid"]))
        create_user(username_to_create["userid"],user_info['UID'],user_info['GID'],user_info["RealName"],default_password)

        ## Add user to groups
        # Copy the standard group list then add admin if requested
        this_users_group_list=list(standardGroupList)
        if username_to_create["admin"]:
            this_users_group_list.append("admin")
        for group in this_users_group_list:
            logging.info("Adding {0} to {1}".format(username_to_create["userid"],group))
            add_user_to_group(username_to_create["userid"],group)

        # Create or chown the homefolder
        create_home_folder("/Users",username_to_create["userid"])

        # Set the password policy
        logging.info("Setting Password policy")
        try:
            set_password_policy(username_to_create["userid"],password_policy)
        except:
            logging.error("Unable to set policy")