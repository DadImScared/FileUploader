import os
import shutil
from unittest import TestCase, main
from flask import abort
from werkzeug.exceptions import NotFound

dir_path = os.path.dirname(os.path.realpath(__file__))
sep = os.path.sep

UPLOAD_FOLDER = "{0}{1}static{1}testing{1}uploads{1}".format(dir_path, sep)
archive = 'archive{}'.format(os.path.sep)
archive_path = UPLOAD_FOLDER + archive

STAGE_ONE_UPLOADS = "stageone{}".format(os.path.sep)
STAGE_TWO_UPLOADS = "stagetwo{}".format(os.path.sep)
STAGE_THREE_UPLOADS = "stagethree{}".format(os.path.sep)
STAGE_FOUR_UPLOADS = "stagefour{}".format(os.path.sep)
FINISHED_FILES_UPLOADS = "finishedfiles{}".format(os.path.sep)

uploads = {
    1: "stage one",
    2: "stage two",
    3: "stage three",
    4: "stage four",
    5: "finished files"
}

upload_path = {
    "stageone": STAGE_ONE_UPLOADS,
    "stagetwo": STAGE_TWO_UPLOADS,
    "stagethree": STAGE_THREE_UPLOADS,
    "stagefour": STAGE_FOUR_UPLOADS,
    "finishedfiles": FINISHED_FILES_UPLOADS
}

directories = [
    ("stageone", "stage one"), ("stagetwo", "stage two"),
    ("stagethree", "stage three"), ("stagefour", "stage four"), ("finishedfiles", "finished files")
]


def reset_test_directories():
    shutil.rmtree(UPLOAD_FOLDER)


def make_test_directory(path):
    os.mkdir(path)


def make_test_directories(path):
    make_test_directory(path)
    make_test_directory(path + "archive")
    for x in directories:
        make_test_directory("{}{}".format(UPLOAD_FOLDER, x[0]))
        make_test_directory("{}archive{}{}".format(UPLOAD_FOLDER, sep, x[0]))


def remove_file(file_path, file_name):
    try:
        os.remove(file_path + file_name)
    except FileNotFoundError:
        pass


def add_file(base_path, sub_directory, file_name, version=None):
    file_path = "{}{}{}".format(base_path, upload_path[sub_directory], file_name) if not version else \
        "{}{}[{}]{}".format(base_path, upload_path[sub_directory], version, file_name)
    mode = 'a' if os.path.exists(file_path) else 'w'
    with open(file_path, mode) as file:
        pass


def move_file(file_to_move, file_destination):
    os.rename(file_to_move, file_destination)


def clone_file(file_to_clone, file_destination):
    try:
        shutil.copyfile(file_to_clone, file_destination)
        return True
    except FileNotFoundError:
        abort(404)


class BaseTestCase(TestCase):
    def setUp(self):
        make_test_directories(UPLOAD_FOLDER)

    def tearDown(self):
        reset_test_directories()

    def test_add_file(self):
        self.assertFalse(os.path.isfile(UPLOAD_FOLDER + upload_path["stageone"] + "work.txt"))
        add_file(UPLOAD_FOLDER, "stageone", "work.txt")
        self.assertTrue(os.path.isfile(UPLOAD_FOLDER + upload_path["stageone"] + "work.txt"))

    def test_remove_file(self):
        self.assertFalse(os.path.isfile(UPLOAD_FOLDER + upload_path["stageone"] + "work.txt"))
        add_file(UPLOAD_FOLDER, "stageone", "work.txt")
        self.assertTrue(os.path.isfile(UPLOAD_FOLDER + upload_path["stageone"] + "work.txt"))
        remove_file(UPLOAD_FOLDER + upload_path["stageone"], "work.txt")
        self.assertFalse(os.path.isfile(UPLOAD_FOLDER + upload_path["stageone"] + "work.txt"))

    def test_move_file(self):
        add_file(UPLOAD_FOLDER, "stageone", "work.txt")
        self.assertTrue(os.path.isfile(UPLOAD_FOLDER + upload_path["stageone"] + "work.txt"))
        move_file(
            "{}{}work.txt".format(UPLOAD_FOLDER, upload_path["stageone"]),
            "{}{}work.txt".format(UPLOAD_FOLDER, upload_path["stagetwo"])
        )
        self.assertTrue(os.path.isfile(UPLOAD_FOLDER + upload_path["stagetwo"] + "work.txt"))
        self.assertFalse(os.path.isfile(UPLOAD_FOLDER + upload_path["stageone"] + "work.txt"))

    def test_clone_file(self):
        self.assertRaises(NotFound, clone_file, "{}{}work.txt".format(UPLOAD_FOLDER, upload_path['stageone']),
                          "{}{}work.txt".format(archive_path, upload_path['stageone']))
        add_file(UPLOAD_FOLDER, "stageone", 'work.txt')
        clone_file(
            "{}{}work.txt".format(UPLOAD_FOLDER, upload_path['stageone']),
            "{}{}work.txt".format(archive_path, upload_path['stageone'])
        )
        self.assertTrue(os.path.isfile(archive_path + upload_path['stageone'] + 'work.txt'))




# make_test_directories(UPLOAD_FOLDER)

name = "".join([UPLOAD_FOLDER, upload_path["stageone"], "testwork.txt"])

# add_file(UPLOAD_FOLDER, "stageone", "testwork.txt")
if __name__ == '__main__':
    main()
