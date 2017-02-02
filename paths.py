
import os

dir_path = os.path.dirname(os.path.realpath(__file__))

UPLOAD_FOLDER = "{0}{1}static{1}uploads{1}".format(dir_path, os.path.sep)

archive = 'archive\\'
archive_path = UPLOAD_FOLDER + archive

def get_path(string):
    if "Archive" in string:
        full_path = UPLOAD_FOLDER + archive + "".join(string.lower().split(" ")[:2]) + os.path.sep
        return full_path

    full_path = UPLOAD_FOLDER + "".join(string.lower().split(" ")[:2]) + os.path.sep
    return full_path


